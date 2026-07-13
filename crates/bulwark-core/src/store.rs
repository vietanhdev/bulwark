//! Persistence, on Diesel.
//!
//! Every query in here is expressed through Diesel's typed DSL rather than as a SQL string. That
//! is not a stylistic preference: the columns a query touches are checked against `schema.rs` at
//! **compile time**, so adding or renaming a column fails the build at every site that needed
//! updating, instead of at runtime on a user's machine — which is precisely how the previous
//! hand-written SQL let a column drift out of sync with the code that read it.
//!
//! The one place raw SQL survives is `PRAGMA` statements and schema introspection, which are not
//! expressible in the DSL by design (they aren't queries over the schema, they're statements
//! *about* it).
//!
//! Three engines, three table pairs, three different reconciliation models — see
//! `migrations/*/up.sql` for why they are deliberately not one table.

use crate::models::{
    Finding, FindingStatus, ScanRun, Severity, Suppression, SuppressionAction, SuppressionEvent,
};
use crate::schema::{
    ai_findings, ai_scan_runs, findings, log_findings, log_scan_runs, rule_suppression_events,
    rule_suppressions, scan_runs, settings,
};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::collections::HashSet;
use std::path::Path;

/// The migrations, compiled into the binary. Nothing at runtime needs the `diesel` CLI or a
/// migrations directory on disk — a packaged `bulwarkctl` or desktop app carries its own schema.
///
/// **Append-only.** A database already stamped with a migration will never re-run it, so editing
/// one silently splits users into two different schemas depending on when they first installed.
/// Add a new migration directory instead.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub struct Store {
    conn: SqliteConnection,
}

/// Sets `0700` (dir) / `0600` (file) on `path`, owner-only. Best-effort and silent on failure:
/// this is a hardening step, not a correctness requirement, and it must never block the tool on a
/// filesystem that doesn't carry Unix modes.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = if meta.is_dir() { 0o700 } else { 0o600 };
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) {}

// ---- row types -----------------------------------------------------------------------------
//
// Diesel maps a table row to a struct. These are the *storage* shapes, kept separate from the
// domain types in `models` — timestamps are RFC 3339 text and UUIDs are text on disk (legible to
// anyone who opens the database with `sqlite3`, which matters for a security tool), and the
// conversion to and from the typed domain model happens here rather than leaking into callers.

#[derive(Queryable, Selectable, Insertable)]
#[diesel(table_name = scan_runs)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct ScanRunRow {
    id: String,
    started_at: String,
    finished_at: Option<String>,
    host_fingerprint: String,
    rules_loaded: i64,
    rules_failed: i64,
    collectors_failed: i64,
    rule_load_errors: String,
    collector_errors: String,
    privileged_skipped: String,
    total_findings: i64,
}

impl ScanRunRow {
    fn from_scan(scan: &ScanRun) -> anyhow::Result<Self> {
        Ok(Self {
            id: scan.id.to_string(),
            started_at: scan.started_at.to_rfc3339(),
            finished_at: scan.finished_at.map(|t| t.to_rfc3339()),
            host_fingerprint: scan.host_fingerprint.clone(),
            rules_loaded: scan.rules_loaded as i64,
            rules_failed: scan.rule_load_errors.len() as i64,
            collectors_failed: scan.collector_errors.len() as i64,
            rule_load_errors: serde_json::to_string(&scan.rule_load_errors)?,
            collector_errors: serde_json::to_string(&scan.collector_errors)?,
            privileged_skipped: serde_json::to_string(&scan.privileged_collectors_skipped)?,
            // The full count the engine produced for *this* scan, independent of how
            // persist_and_reconcile later reassigns individual findings' scan_run_id to whichever
            // run most recently observed them — that reassignment is about "what does the
            // dashboard show right now", this column is about "what did this point in time look
            // like", which is what the History view needs.
            total_findings: scan.findings.len() as i64,
        })
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = rule_suppressions)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct SuppressionRow {
    rule_id: String,
    reason: String,
    created_at: String,
    created_by: String,
}

impl SuppressionRow {
    fn try_into_model(self) -> anyhow::Result<Suppression> {
        Ok(Suppression {
            rule_id: self.rule_id,
            reason: self.reason,
            created_at: parse_audit_ts(&self.created_at)?,
            created_by: self.created_by,
        })
    }
}

/// Strict timestamp parsing, unlike [`parse_ts`], which falls back to `Utc::now()` on a bad value.
///
/// That fallback is fine for a scan row — a slightly wrong "last seen" is cosmetic. It is not fine
/// here. An audit entry whose timestamp silently becomes *now* whenever it fails to parse is an
/// audit entry that lies, and it lies in the most misleading possible direction: a corrupted or
/// tampered record would read as having just been written. Refusing to load it is the honest
/// failure, so this errors instead.
fn parse_audit_ts(s: &str) -> anyhow::Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)
        .map_err(|e| anyhow::anyhow!("corrupt timestamp in suppression audit log ({s:?}): {e}"))?
        .with_timezone(&Utc))
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = rule_suppression_events)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct SuppressionEventRow {
    id: String,
    rule_id: String,
    action: String,
    reason: String,
    actor: String,
    at: String,
}

impl SuppressionEventRow {
    fn try_into_model(self) -> anyhow::Result<SuppressionEvent> {
        let action = match self.action.as_str() {
            "suppressed" => SuppressionAction::Suppressed,
            "unsuppressed" => SuppressionAction::Unsuppressed,
            other => anyhow::bail!("unknown suppression action in audit log: {other}"),
        };
        Ok(SuppressionEvent {
            id: self.id.parse()?,
            rule_id: self.rule_id,
            action,
            reason: self.reason,
            actor: self.actor,
            at: parse_audit_ts(&self.at)?,
        })
    }
}

/// Writes one immutable entry to the audit trail. Shared by suppress and unsuppress so that both
/// paths are structurally incapable of forgetting to log — the only way to change a suppression is
/// through a function that also records having changed it.
fn append_suppression_event(
    conn: &mut SqliteConnection,
    rule_id: &str,
    action: SuppressionAction,
    reason: &str,
    actor: &str,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    diesel::insert_into(rule_suppression_events::table)
        .values((
            rule_suppression_events::id.eq(uuid::Uuid::new_v4().to_string()),
            rule_suppression_events::rule_id.eq(rule_id),
            rule_suppression_events::action.eq(action.as_str()),
            rule_suppression_events::reason.eq(reason),
            rule_suppression_events::actor.eq(actor),
            rule_suppression_events::at.eq(at.to_rfc3339()),
        ))
        .execute(conn)?;
    Ok(())
}

#[derive(Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = findings)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct FindingRow {
    id: String,
    scan_run_id: String,
    rule_id: String,
    severity: String,
    title: String,
    explanation: String,
    fix_hint: String,
    context: String,
    first_seen: String,
    last_seen: String,
    status: String,
}

impl FindingRow {
    fn from_finding(f: &Finding) -> anyhow::Result<Self> {
        Ok(Self {
            id: f.id.to_string(),
            scan_run_id: f.scan_run_id.to_string(),
            rule_id: f.rule_id.clone(),
            severity: severity_str(f.severity).to_string(),
            title: f.title.clone(),
            explanation: f.explanation.clone(),
            fix_hint: f.fix_hint.clone(),
            context: serde_json::to_string(&f.context)?,
            first_seen: f.first_seen.to_rfc3339(),
            last_seen: f.last_seen.to_rfc3339(),
            status: status_str(f.status).to_string(),
        })
    }

    /// Fallible on purpose. A row whose `id`/`scan_run_id` isn't a UUID was never written by
    /// Bulwark, but "can't happen" is not a licence to silently substitute a nil UUID and carry on
    /// — that's the silent-corruption failure mode this project refuses everywhere else. It
    /// surfaces as an error instead.
    fn try_into_finding(self) -> anyhow::Result<Finding> {
        Ok(Finding {
            id: self
                .id
                .parse()
                .map_err(|e| anyhow::anyhow!("findings.id '{}' is not a UUID: {e}", self.id))?,
            scan_run_id: self.scan_run_id.parse().map_err(|e| {
                anyhow::anyhow!(
                    "findings.scan_run_id '{}' is not a UUID: {e}",
                    self.scan_run_id
                )
            })?,
            rule_id: self.rule_id,
            severity: parse_severity(&self.severity),
            title: self.title,
            explanation: self.explanation,
            fix_hint: self.fix_hint,
            context: serde_json::from_str(&self.context).unwrap_or_default(),
            first_seen: parse_ts(&self.first_seen),
            last_seen: parse_ts(&self.last_seen),
            status: parse_status(&self.status),
        })
    }
}

#[derive(Queryable, Selectable, Insertable)]
#[diesel(table_name = log_scan_runs)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct LogScanRunRow {
    id: String,
    started_at: String,
    finished_at: Option<String>,
    host_fingerprint: String,
    events_read: i64,
    events_decoded: i64,
    decoders_loaded: i64,
    rules_loaded: i64,
    total_findings: i64,
    decoder_load_errors: String,
    rule_load_errors: String,
    read_errors: String,
    rule_eval_errors: String,
}

#[derive(Queryable, Selectable, Insertable)]
#[diesel(table_name = log_findings)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct LogFindingRow {
    id: String,
    log_scan_run_id: String,
    rule_id: String,
    severity: String,
    category: String,
    title: String,
    explanation: String,
    fix_hint: String,
    group_key: String,
    match_count: i64,
    context: String,
    refs: String,
    observed_at: String,
    first_seen: String,
    last_seen: String,
    occurrences: i64,
}

#[derive(Queryable, Selectable, Insertable)]
#[diesel(table_name = ai_scan_runs)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct AiScanRunRow {
    id: String,
    started_at: String,
    finished_at: Option<String>,
    host_fingerprint: String,
    workspaces_scanned: String,
    artifacts_scanned: i64,
    total_findings: i64,
    workspaces_capped: bool,
    scan_errors: String,
}

#[derive(Queryable, Selectable, Insertable)]
#[diesel(table_name = ai_findings)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct AiFindingRow {
    id: String,
    ai_scan_run_id: String,
    rule_id: String,
    severity: String,
    tool: String,
    title: String,
    explanation: String,
    fix_hint: String,
    file: String,
    line: Option<i64>,
    evidence: String,
    refs: String,
    redactable: bool,
}

impl AiFindingRow {
    fn from_finding(f: &crate::ai_scan::AiFinding, run_id: &str) -> anyhow::Result<Self> {
        Ok(Self {
            id: f.id.to_string(),
            ai_scan_run_id: run_id.to_string(),
            rule_id: f.rule_id.clone(),
            severity: severity_str(f.severity).to_string(),
            tool: f.tool.clone(),
            title: f.title.clone(),
            explanation: f.explanation.clone(),
            fix_hint: f.fix_hint.clone(),
            file: f.file.clone(),
            line: f.line.map(|l| l as i64),
            evidence: f.evidence.clone(),
            refs: serde_json::to_string(&f.references)?,
            redactable: f.redactable,
        })
    }

    fn try_into_finding(self) -> anyhow::Result<crate::ai_scan::AiFinding> {
        Ok(crate::ai_scan::AiFinding {
            id: self
                .id
                .parse()
                .map_err(|e| anyhow::anyhow!("ai_findings.id '{}' is not a UUID: {e}", self.id))?,
            rule_id: self.rule_id,
            severity: parse_severity(&self.severity),
            tool: self.tool,
            title: self.title,
            explanation: self.explanation,
            fix_hint: self.fix_hint,
            file: self.file,
            line: self.line.map(|l| l as usize),
            evidence: self.evidence,
            references: serde_json::from_str(&self.refs).unwrap_or_default(),
            redactable: self.redactable,
        })
    }
}

impl Store {
    /// Opens (creating if needed) the database at `path` and brings its schema up to date.
    ///
    /// A database written by a pre-Diesel build is **moved aside**, not migrated: Bulwark's
    /// findings are a cache of host state, re-derived by the next scan, so there is nothing in
    /// there worth the risk of a bespoke cross-framework migration. The old file is preserved as
    /// `<name>.pre-orm.bak` rather than deleted — it is the user's data, even if we no longer read
    /// it — and the fact is logged rather than done silently.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            // The database is a catalogue of this host's security weaknesses (open findings, fix
            // hints) plus masked-secret evidence and secret file paths — an attacker's prioritized
            // target list if another local user can read it. Lock down the directory and (below)
            // the file to owner-only, rather than inheriting a world-readable default umask.
            restrict_to_owner(parent);
        }
        if is_pre_orm_database(path)? {
            let backup = path.with_extension("db.pre-orm.bak");
            std::fs::rename(path, &backup)?;
            eprintln!(
                "[bulwark] the findings database predates the current schema; it has been kept at \
                 {} and a fresh one created. Findings are rebuilt by the next scan.",
                backup.display()
            );
        }

        let url = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("database path is not valid UTF-8"))?;
        let mut conn = SqliteConnection::establish(url)?;
        prepare(&mut conn)?;
        // `establish` creates the file under the process umask (typically 0644, world-readable);
        // tighten it to owner-only now that it exists. Best-effort: a failure here (e.g. a
        // filesystem without Unix modes) must not stop the tool from working.
        restrict_to_owner(path);
        Ok(Self { conn })
    }

    /// An ephemeral database, for tests.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let mut conn = SqliteConnection::establish(":memory:")?;
        prepare(&mut conn)?;
        Ok(Self { conn })
    }

    /// True once every embedded migration has been applied — i.e. the schema is current.
    pub fn is_schema_current(&mut self) -> anyhow::Result<bool> {
        self.conn
            .has_pending_migration(MIGRATIONS)
            .map(|pending| !pending)
            .map_err(|e| anyhow::anyhow!("checking migrations: {e}"))
    }

    /// Inserts a scan and all of its findings verbatim. No reconciliation — every finding becomes
    /// a new row. Used where a raw record of one run is wanted; the monitoring/scan paths use
    /// [`Self::persist_and_reconcile`] instead.
    pub fn persist(&mut self, scan: &ScanRun) -> anyhow::Result<()> {
        self.conn.transaction(|conn| {
            diesel::insert_into(scan_runs::table)
                .values(ScanRunRow::from_scan(scan)?)
                .execute(conn)?;
            for f in &scan.findings {
                diesel::insert_into(findings::table)
                    .values(FindingRow::from_finding(f)?)
                    .execute(conn)?;
            }
            Ok::<_, anyhow::Error>(())
        })
    }

    /// Persists a `ScanRun` the way continuous monitoring needs.
    ///
    /// A finding matching an already-*open* finding from a previous run has its `last_seen` (and
    /// stored context) updated in place rather than becoming a duplicate row, and keeps its
    /// original `first_seen`. Anything left over — genuinely new, or a rule_id+context that was
    /// previously resolved and has reappeared — is inserted fresh and returned as "newly
    /// appeared", which is what should actually trigger a notification.
    ///
    /// **Fixed issues are closed, but only when the scan can prove they're fixed.** An open row
    /// whose rule is in `scan.rules_evaluated` (the rule demonstrably ran and evaluated cleanly)
    /// and which nothing in this scan matched is marked `resolved`. A row whose rule is *not* in
    /// that list — its collector was skipped for lack of privilege, was inapplicable, errored, or
    /// the scan was stopped before reaching it — is left untouched, because absence proves nothing
    /// there. Before this distinction existed the reconciler could only ever add findings, so a
    /// remediated issue stayed on the dashboard forever: recording a file-integrity baseline left
    /// "no baseline yet" on screen permanently even though every later scan came back clean.
    ///
    /// "Same underlying issue" is *not* exact-string equality on the serialized context. A real
    /// bug caught in this project's own dashboard: extending `login_defs.rs` to add two new
    /// always-present fields changed the context JSON shape for the *existing* `BLWK-ACCT-002`
    /// rule (which doesn't even read those fields), which broke the old exact-match query and
    /// produced a second row for the same real-world issue on the very next scan. A collector's
    /// fact shape evolving is routine, so the identity check tolerates it: a stored context
    /// matches if it's a *subset* of the newly observed one. Two genuinely different rows from a
    /// list-shaped collector still can't cross-match, since their discriminating field differs.
    pub fn persist_and_reconcile(&mut self, scan: &ScanRun) -> anyhow::Result<Vec<Finding>> {
        self.conn.transaction(|conn| {
            diesel::insert_into(scan_runs::table)
                .values(ScanRunRow::from_scan(scan)?)
                .execute(conn)?;

            let mut newly_appeared = Vec::new();
            // Every pre-existing open row this scan re-observed. Whatever is left over — for a
            // rule that demonstrably ran — is a fixed issue, and gets closed below.
            let mut matched_ids: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            for f in &scan.findings {
                let candidates: Vec<(String, String)> = findings::table
                    .filter(findings::rule_id.eq(&f.rule_id))
                    .filter(findings::status.eq("open"))
                    .select((findings::id, findings::context))
                    .load(conn)?;

                let existing_id = candidates.into_iter().find_map(|(id, context_json)| {
                    if matched_ids.contains(&id) {
                        // Already claimed by an earlier finding in this same scan — a list-shaped
                        // collector's two rows must not both reconcile onto one stored row.
                        return None;
                    }
                    let old: crate::models::Fact = serde_json::from_str(&context_json).ok()?;
                    is_context_subset(&old, &f.context).then_some(id)
                });

                match existing_id {
                    Some(id) => {
                        diesel::update(findings::table.find(&id))
                            .set((
                                findings::last_seen.eq(f.last_seen.to_rfc3339()),
                                findings::scan_run_id.eq(f.scan_run_id.to_string()),
                                findings::context.eq(serde_json::to_string(&f.context)?),
                            ))
                            .execute(conn)?;
                        matched_ids.insert(id);
                    }
                    None => {
                        diesel::insert_into(findings::table)
                            .values(FindingRow::from_finding(f)?)
                            .execute(conn)?;
                        // Register it as observed by *this* scan, or the resolve pass below would
                        // immediately close the row we just inserted — it is, after all, an open
                        // row for an evaluated rule that nothing has "matched".
                        matched_ids.insert(f.id.to_string());
                        newly_appeared.push(f.clone());
                    }
                }
            }

            // Close what's demonstrably fixed.
            for rule_id in &scan.rules_evaluated {
                let open_ids: Vec<String> = findings::table
                    .filter(findings::rule_id.eq(rule_id))
                    .filter(findings::status.eq("open"))
                    .select(findings::id)
                    .load(conn)?;

                let stale: Vec<String> = open_ids
                    .into_iter()
                    .filter(|id| !matched_ids.contains(id))
                    .collect();
                if stale.is_empty() {
                    continue;
                }
                diesel::update(findings::table.filter(findings::id.eq_any(&stale)))
                    .set((
                        findings::status.eq("resolved"),
                        findings::last_seen.eq(scan.started_at.to_rfc3339()),
                    ))
                    .execute(conn)?;
            }

            // Stamp this run's `total_findings` with the reconciled OPEN count, not the raw number
            // this scan happened to observe. The History view trends open issues over time, and a
            // narrow tick — unprivileged, or a desktop-profile run that never loads the server
            // rules — observes fewer findings than are actually open, because reconciliation
            // correctly carries forward everything it can't disprove. Recording the raw per-scan
            // count (`scan.findings.len()`, set at insert above) made History underreport and
            // flat-line at whatever the monitoring tick saw, disagreeing with the Overview's open
            // count. The reconciled open total is the real posture of the host as of this run.
            let open_count: i64 = findings::table
                .filter(findings::status.eq("open"))
                .count()
                .get_result(conn)?;
            diesel::update(scan_runs::table.find(scan.id.to_string()))
                .set(scan_runs::total_findings.eq(open_count))
                .execute(conn)?;

            Ok::<_, anyhow::Error>(newly_appeared)
        })
    }

    pub fn count_scan_runs(&mut self) -> anyhow::Result<i64> {
        Ok(scan_runs::table.count().get_result(&mut self.conn)?)
    }

    pub fn count_findings_for_run(&mut self, scan_run_id: &str) -> anyhow::Result<i64> {
        Ok(findings::table
            .filter(findings::scan_run_id.eq(scan_run_id))
            .count()
            .get_result(&mut self.conn)?)
    }

    /// Persists a [`LogScanRun`](crate::logs::LogScanRun), reconciling on `(rule_id, group_key)` —
    /// the log analog of [`Self::persist_and_reconcile`]. A finding whose `(rule_id, group_key)`
    /// already exists updates that row's `last_seen`/`match_count` and bumps an `occurrences`
    /// counter in place (a brute-force from the same IP recurring across batches is one row that
    /// "keeps happening", not a flood of duplicates), keeping its original `first_seen`. Genuinely
    /// new pairs are inserted and returned as "newly appeared".
    ///
    /// Identity here is an exact `(rule_id, group_key)` match rather than a context subset:
    /// `group_key` is already the natural correlation identity (the source IP, the user), so
    /// there's nothing to tolerate — two different keys are two genuinely different alerts.
    pub fn persist_log_scan(
        &mut self,
        scan: &crate::logs::LogScanRun,
    ) -> anyhow::Result<Vec<crate::logs::LogFinding>> {
        self.conn.transaction(|conn| {
            diesel::insert_into(log_scan_runs::table)
                .values(LogScanRunRow {
                    id: scan.id.to_string(),
                    started_at: scan.started_at.to_rfc3339(),
                    finished_at: scan.finished_at.map(|t| t.to_rfc3339()),
                    host_fingerprint: scan.host_fingerprint.clone(),
                    events_read: scan.events_read as i64,
                    events_decoded: scan.events_decoded as i64,
                    decoders_loaded: scan.decoders_loaded as i64,
                    rules_loaded: scan.rules_loaded as i64,
                    total_findings: scan.findings.len() as i64,
                    decoder_load_errors: serde_json::to_string(&scan.decoder_load_errors)?,
                    rule_load_errors: serde_json::to_string(&scan.rule_load_errors)?,
                    read_errors: serde_json::to_string(&scan.read_errors)?,
                    rule_eval_errors: serde_json::to_string(&scan.rule_eval_errors)?,
                })
                .execute(conn)?;

            let mut newly_appeared = Vec::new();
            for f in &scan.findings {
                let existing: Option<String> = log_findings::table
                    .filter(log_findings::rule_id.eq(&f.rule_id))
                    .filter(log_findings::group_key.eq(&f.group_key))
                    .select(log_findings::id)
                    .first(conn)
                    .optional()?;

                match existing {
                    Some(id) => {
                        diesel::update(log_findings::table.find(&id))
                            .set((
                                log_findings::last_seen.eq(f.observed_at.to_rfc3339()),
                                log_findings::match_count.eq(f.match_count as i64),
                                log_findings::log_scan_run_id.eq(scan.id.to_string()),
                                log_findings::occurrences.eq(log_findings::occurrences + 1),
                            ))
                            .execute(conn)?;
                    }
                    None => {
                        diesel::insert_into(log_findings::table)
                            .values(LogFindingRow {
                                id: f.id.to_string(),
                                log_scan_run_id: scan.id.to_string(),
                                rule_id: f.rule_id.clone(),
                                severity: severity_str(f.severity).to_string(),
                                category: f.category.clone(),
                                title: f.title.clone(),
                                explanation: f.explanation.clone(),
                                fix_hint: f.fix_hint.clone(),
                                group_key: f.group_key.clone(),
                                match_count: f.match_count as i64,
                                context: serde_json::to_string(&f.context)?,
                                refs: serde_json::to_string(&f.references)?,
                                observed_at: f.observed_at.to_rfc3339(),
                                first_seen: f.observed_at.to_rfc3339(),
                                last_seen: f.observed_at.to_rfc3339(),
                                occurrences: 1,
                            })
                            .execute(conn)?;
                        newly_appeared.push(f.clone());
                    }
                }
            }
            Ok::<_, anyhow::Error>(newly_appeared)
        })
    }

    pub fn count_log_scan_runs(&mut self) -> anyhow::Result<i64> {
        Ok(log_scan_runs::table.count().get_result(&mut self.conn)?)
    }

    pub fn count_log_findings(&mut self) -> anyhow::Result<i64> {
        Ok(log_findings::table.count().get_result(&mut self.conn)?)
    }

    /// Persists one agent-artifact scan. Unlike [`Self::persist_and_reconcile`], this is
    /// latest-run-wins with no cross-run reconciliation: each scan inserts a fresh run and its
    /// findings, and the snapshot always reads the most recent one. That is the right model for
    /// artifact scanning specifically — a secret the user has since redacted, or a config they've
    /// fixed, should simply be *gone* from the next scan, whereas the config reconciler
    /// deliberately keeps a finding open when the check that would have cleared it never ran.
    pub fn persist_ai_scan(&mut self, report: &crate::ai_scan::AiScanReport) -> anyhow::Result<()> {
        self.conn.transaction(|conn| {
            let run_id = report.id.to_string();
            diesel::insert_into(ai_scan_runs::table)
                .values(AiScanRunRow {
                    id: run_id.clone(),
                    started_at: report.started_at.to_rfc3339(),
                    finished_at: report.finished_at.map(|t| t.to_rfc3339()),
                    host_fingerprint: report.host_fingerprint.clone(),
                    workspaces_scanned: serde_json::to_string(&report.workspaces_scanned)?,
                    artifacts_scanned: report.artifacts_scanned as i64,
                    total_findings: report.findings.len() as i64,
                    workspaces_capped: report.workspaces_capped,
                    scan_errors: serde_json::to_string(&report.errors)?,
                })
                .execute(conn)?;

            for f in &report.findings {
                diesel::insert_into(ai_findings::table)
                    .values(AiFindingRow::from_finding(f, &run_id)?)
                    .execute(conn)?;
            }

            // Agent scans are latest-run-wins: only the newest run's findings are ever read (see
            // `latest_ai_scan`), so every earlier run's *detail* rows are dead weight. A machine
            // left monitoring accumulates thousands of them (a real DB reached 3,819 rows across ten
            // runs while only 243 were live), which both bloats the file and makes the stored data
            // look wildly out of step with what the tabs show. Prune the stale detail here, keeping
            // this run's rows. The per-run summary rows in `ai_scan_runs` are deliberately retained —
            // they're tiny and carry `total_findings`, which is what a findings-over-time view needs
            // — so nothing a user can actually see is lost, only redundant detail.
            diesel::delete(ai_findings::table.filter(ai_findings::ai_scan_run_id.ne(&run_id)))
                .execute(conn)?;

            Ok::<_, anyhow::Error>(())
        })
    }

    /// Drops the redactable (secret-leak) findings for the given files from the latest agent scan,
    /// returning how many rows were removed. Called right after a successful in-place redaction:
    /// the secrets are gone from disk, so the stored snapshot must stop reporting them — but a full
    /// re-scan to achieve that would re-walk the entire home directory (minutes on a large one),
    /// which is exactly the cost the Agent Security tab's redact flow was paying. This surgically
    /// removes just the findings the redaction resolved, keeping the persisted snapshot honest
    /// without re-scanning anything.
    ///
    /// Only `redactable` rows are touched: a file can also carry non-secret findings (a dangerous
    /// MCP config, say), and redaction did not address those, so they must remain.
    pub fn remove_redacted_ai_findings(&mut self, files: &[String]) -> anyhow::Result<usize> {
        if files.is_empty() {
            return Ok(0);
        }
        let Some(run_id): Option<String> = ai_scan_runs::table
            .order(ai_scan_runs::started_at.desc())
            .select(ai_scan_runs::id)
            .first(&mut self.conn)
            .optional()?
        else {
            return Ok(0);
        };
        let removed = diesel::delete(
            ai_findings::table
                .filter(ai_findings::ai_scan_run_id.eq(&run_id))
                .filter(ai_findings::redactable.eq(true))
                .filter(ai_findings::file.eq_any(files)),
        )
        .execute(&mut self.conn)?;
        Ok(removed)
    }

    /// The most recent agent scan's summary and findings, or `None` if none has run — what a
    /// freshly-opened Agent Security tab shows without forcing a re-scan first.
    pub fn latest_ai_scan(&mut self) -> anyhow::Result<Option<AiScanSnapshot>> {
        let run: Option<AiScanRunRow> = ai_scan_runs::table
            .order(ai_scan_runs::started_at.desc())
            .select(AiScanRunRow::as_select())
            .first(&mut self.conn)
            .optional()?;

        let Some(run) = run else { return Ok(None) };

        let rows: Vec<AiFindingRow> = ai_findings::table
            .filter(ai_findings::ai_scan_run_id.eq(&run.id))
            .select(AiFindingRow::as_select())
            .load(&mut self.conn)?;

        Ok(Some(AiScanSnapshot {
            started_at: parse_ts(&run.started_at),
            host_fingerprint: run.host_fingerprint,
            workspaces_scanned: serde_json::from_str(&run.workspaces_scanned)?,
            artifacts_scanned: run.artifacts_scanned as usize,
            workspaces_capped: run.workspaces_capped,
            findings: rows
                .into_iter()
                .map(AiFindingRow::try_into_finding)
                .collect::<anyhow::Result<Vec<_>>>()?,
        }))
    }

    /// Generic string key-value read, backing small persisted preferences (monitoring interval,
    /// real-time AV toggle, agent-scan roots) that don't warrant a table of their own. Callers own
    /// their value encoding; this just stores and returns text.
    pub fn get_setting(&mut self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(settings::table
            .find(key)
            .select(settings::value)
            .first(&mut self.conn)
            .optional()?)
    }

    /// Upserts a setting — the counterpart to [`Self::get_setting`].
    pub fn set_setting(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        diesel::insert_into(settings::table)
            .values((settings::key.eq(key), settings::value.eq(value)))
            .on_conflict(settings::key)
            .do_update()
            .set(settings::value.eq(value))
            .execute(&mut self.conn)?;
        Ok(())
    }

    /// Records a user's decision to accept the risk a rule reports, with their reasoning.
    ///
    /// The reason is validated **here**, in core, rather than in the UI form — otherwise
    /// `bulwarkctl` (or any future caller) could write an unexplained suppression straight past the
    /// check, and the audit trail would have holes exactly where someone was in a hurry. A blank
    /// reason is the one thing that makes the whole feature worthless six months later, when the
    /// person asking "why is this muted?" is the person who muted it.
    ///
    /// Re-suppressing an already-suppressed rule is allowed and overwrites the reason: people
    /// refine their justifications. Every attempt appends to the audit log regardless, so the
    /// earlier reasoning is never lost, only superseded.
    pub fn suppress_rule(
        &mut self,
        rule_id: &str,
        reason: &str,
        actor: &str,
    ) -> anyhow::Result<Suppression> {
        let reason = reason.trim();
        if reason.is_empty() {
            anyhow::bail!("a suppression needs a reason — an unexplained one is unauditable");
        }
        let now = Utc::now();
        let suppression = Suppression {
            rule_id: rule_id.to_string(),
            reason: reason.to_string(),
            created_at: now,
            created_by: actor.to_string(),
        };

        // State and audit entry go in together: an audit log that can disagree with the state it
        // describes is worse than no audit log, because it is trusted and wrong.
        self.conn.transaction::<_, anyhow::Error, _>(|conn| {
            diesel::insert_into(rule_suppressions::table)
                .values((
                    rule_suppressions::rule_id.eq(rule_id),
                    rule_suppressions::reason.eq(reason),
                    rule_suppressions::created_at.eq(now.to_rfc3339()),
                    rule_suppressions::created_by.eq(actor),
                ))
                .on_conflict(rule_suppressions::rule_id)
                .do_update()
                .set((
                    rule_suppressions::reason.eq(reason),
                    rule_suppressions::created_at.eq(now.to_rfc3339()),
                    rule_suppressions::created_by.eq(actor),
                ))
                .execute(conn)?;
            append_suppression_event(
                conn,
                rule_id,
                SuppressionAction::Suppressed,
                reason,
                actor,
                now,
            )?;
            Ok(())
        })?;
        Ok(suppression)
    }

    /// Lifts a suppression. Also requires a reason — withdrawing a risk acceptance is every bit as
    /// much an auditable decision as making one, and "why did this alert come back?" is a question
    /// someone will eventually ask.
    ///
    /// The `rule_suppressions` row is deleted; the audit trail is not. That asymmetry is the design:
    /// state is current, history is forever.
    pub fn unsuppress_rule(
        &mut self,
        rule_id: &str,
        reason: &str,
        actor: &str,
    ) -> anyhow::Result<()> {
        let reason = reason.trim();
        if reason.is_empty() {
            anyhow::bail!("lifting a suppression needs a reason too — it is an auditable decision");
        }
        let now = Utc::now();
        self.conn.transaction::<_, anyhow::Error, _>(|conn| {
            let removed = diesel::delete(rule_suppressions::table.find(rule_id)).execute(conn)?;
            if removed == 0 {
                anyhow::bail!("rule {rule_id} is not suppressed");
            }
            append_suppression_event(
                conn,
                rule_id,
                SuppressionAction::Unsuppressed,
                reason,
                actor,
                now,
            )?;
            Ok(())
        })
    }

    /// Every currently-active suppression, newest first.
    pub fn list_suppressions(&mut self) -> anyhow::Result<Vec<Suppression>> {
        let rows: Vec<SuppressionRow> = rule_suppressions::table
            .order(rule_suppressions::created_at.desc())
            .select(SuppressionRow::as_select())
            .load(&mut self.conn)?;
        rows.into_iter()
            .map(SuppressionRow::try_into_model)
            .collect()
    }

    /// Just the rule IDs, for the hot path: every findings query needs to know which rules are
    /// muted so it can partition them out, and it does not need the reasons to do it.
    pub fn suppressed_rule_ids(&mut self) -> anyhow::Result<HashSet<String>> {
        Ok(rule_suppressions::table
            .select(rule_suppressions::rule_id)
            .load::<String>(&mut self.conn)?
            .into_iter()
            .collect())
    }

    /// The append-only audit trail, newest first. Pass `rule_id` to scope it to one rule's history.
    ///
    /// This deliberately reads from the events table and never from `rule_suppressions`, so a rule
    /// that was suppressed and later un-suppressed still tells its full story — which is the only
    /// reason to keep two tables in the first place.
    pub fn suppression_audit_log(
        &mut self,
        rule_id: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<SuppressionEvent>> {
        let mut q = rule_suppression_events::table.into_boxed();
        if let Some(id) = rule_id {
            q = q.filter(rule_suppression_events::rule_id.eq(id.to_string()));
        }
        let rows: Vec<SuppressionEventRow> = q
            .order(rule_suppression_events::at.desc())
            .limit(limit)
            .select(SuppressionEventRow::as_select())
            .load(&mut self.conn)?;
        rows.into_iter()
            .map(SuppressionEventRow::try_into_model)
            .collect()
    }

    /// The state a freshly-opened window should show: everything currently open, regardless of
    /// whether it was last touched by a manual scan or a background monitoring tick. Reconciliation
    /// is what makes `status = 'open'` mean "the current picture" rather than "whatever the single
    /// latest run happened to see" — a privileged finding only ever observed by an earlier manual
    /// privileged scan is still legitimately open even if the most recent tick was unprivileged.
    ///
    /// Suppressed rules are *not* filtered out here. Callers get the honest, complete list and
    /// partition it themselves via [`Self::suppressed_rule_ids`] — see [`Self::open_findings_split`],
    /// which is what the UI actually wants. Hiding accepted risk this far down the stack would make
    /// it invisible to every caller, including the ones whose job is to report it.
    pub fn open_findings(&mut self) -> anyhow::Result<Vec<Finding>> {
        let rows: Vec<FindingRow> = findings::table
            .filter(findings::status.eq("open"))
            .order(findings::last_seen.desc())
            .select(FindingRow::as_select())
            .load(&mut self.conn)?;
        rows.into_iter().map(FindingRow::try_into_finding).collect()
    }

    /// Open findings, partitioned into the ones the user still needs to act on and the ones they
    /// have explicitly accepted the risk of. This is what the UI should call.
    ///
    /// Returning both halves rather than silently dropping the suppressed ones is the point. A
    /// security tool that hides accepted risk is lying by omission: the risk is still there, someone
    /// just decided to live with it, and the count of what they decided to live with is exactly the
    /// number a reviewer wants to see. "0 issues" and "0 issues, 14 suppressed" are very different
    /// sentences, and the UI is entitled to say the second one.
    pub fn open_findings_split(&mut self) -> anyhow::Result<SplitFindings> {
        let suppressed_ids = self.suppressed_rule_ids()?;
        let (suppressed, active) = self
            .open_findings()?
            .into_iter()
            .partition(|f| suppressed_ids.contains(&f.rule_id));
        Ok(SplitFindings { active, suppressed })
    }

    /// Metadata for the most recent scan run — host fingerprint, when it started, and which
    /// collectors it had to skip for lack of privilege — so a freshly-opened window can show "last
    /// checked ..." and the privileged-checks banner without the user re-scanning first.
    pub fn latest_scan_run_meta(&mut self) -> anyhow::Result<Option<LatestScanMeta>> {
        let row: Option<(String, String, String)> = scan_runs::table
            .order(scan_runs::started_at.desc())
            .select((
                scan_runs::host_fingerprint,
                scan_runs::started_at,
                scan_runs::privileged_skipped,
            ))
            .first(&mut self.conn)
            .optional()?;

        row.map(|(host_fingerprint, started_at, skipped)| {
            Ok(LatestScanMeta {
                host_fingerprint,
                started_at: DateTime::parse_from_rfc3339(&started_at)?.with_timezone(&Utc),
                privileged_collectors_skipped: serde_json::from_str(&skipped)?,
            })
        })
        .transpose()
    }

    /// The most recent `limit` scan runs, newest first — backs the History timeline. Its
    /// `total_findings` is what that specific scan produced, not a live re-derived count, so the
    /// trend stays accurate even as later runs reconcile finding rows onto themselves.
    pub fn list_scan_runs(&mut self, limit: i64) -> anyhow::Result<Vec<ScanRunSummary>> {
        let rows: Vec<ScanRunRow> = scan_runs::table
            .order(scan_runs::started_at.desc())
            .limit(limit)
            .select(ScanRunRow::as_select())
            .load(&mut self.conn)?;

        Ok(rows
            .into_iter()
            .map(|r| ScanRunSummary {
                id: r.id,
                started_at: parse_ts(&r.started_at),
                finished_at: r.finished_at.as_deref().map(parse_ts),
                host_fingerprint: r.host_fingerprint,
                rules_loaded: r.rules_loaded,
                rules_failed: r.rules_failed,
                collectors_failed: r.collectors_failed,
                privileged_collectors_skipped: serde_json::from_str(&r.privileged_skipped)
                    .unwrap_or_default(),
                total_findings: r.total_findings,
            })
            .collect())
    }
}

/// Turns a bare connection into a usable Bulwark database: foreign keys on, schema current.
///
/// `PRAGMA` is one of the two things Diesel's DSL deliberately can't express (it isn't a query
/// over the schema, it's a statement about the connection), so it stays raw SQL. Foreign keys are
/// **off by default in SQLite** and must be enabled per connection — without this the
/// `findings.scan_run_id -> scan_runs.id` reference is decoration rather than a constraint.
fn prepare(conn: &mut SqliteConnection) -> anyhow::Result<()> {
    diesel::sql_query("PRAGMA foreign_keys = ON").execute(conn)?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("running migrations: {e}"))?;
    Ok(())
}

/// True when `path` holds a database written before the store moved to Diesel: it has Bulwark's
/// tables but not Diesel's migration bookkeeping. Schema introspection, like `PRAGMA`, is not
/// something the typed DSL models — it's a question *about* the schema rather than a query over it.
fn is_pre_orm_database(path: &Path) -> anyhow::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let url = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("database path is not valid UTF-8"))?;
    let mut conn = SqliteConnection::establish(url)?;

    #[derive(QueryableByName)]
    struct TableName {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }

    let tables: Vec<TableName> =
        diesel::sql_query("SELECT name FROM sqlite_master WHERE type = 'table'").load(&mut conn)?;
    let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();

    Ok(names.contains(&"findings") && !names.contains(&"__diesel_schema_migrations"))
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

/// True if every key `old` has is present in `new` with an equal value — `old` needn't be a
/// *proper* subset (equal maps count), and `new` may carry extra keys `old` never had. This is
/// `persist_and_reconcile`'s identity check for "the same underlying issue": exact equality on the
/// full context would mean a collector gaining a new field (routine) breaks continuity for every
/// existing rule reading that collector, even ones that never touch the new field.
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

/// Open findings split by whether the user has accepted their risk. `suppressed` is not "hidden" —
/// it's a number the UI is expected to show, because the honest summary of a scan is "3 to fix, 2
/// accepted", not "3 to fix".
#[derive(Debug, Clone, serde::Serialize)]
pub struct SplitFindings {
    pub active: Vec<Finding>,
    pub suppressed: Vec<Finding>,
}

#[derive(serde::Serialize)]
pub struct LatestScanMeta {
    pub host_fingerprint: String,
    pub started_at: DateTime<Utc>,
    pub privileged_collectors_skipped: Vec<String>,
}

/// The most recent agent scan, reconstructed from storage — summary plus findings. Backs the Agent
/// Security tab's "show the last scan on open", as [`LatestScanMeta`] + `open_findings` do for the
/// config dashboard.
#[derive(serde::Serialize)]
pub struct AiScanSnapshot {
    pub started_at: DateTime<Utc>,
    pub host_fingerprint: String,
    pub workspaces_scanned: Vec<String>,
    pub artifacts_scanned: usize,
    pub workspaces_capped: bool,
    pub findings: Vec<crate::ai_scan::AiFinding>,
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
            rules_evaluated: vec!["BLWK-SSH-001".into()],
            cancelled: false,
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
    fn a_suppression_without_a_reason_is_refused() {
        let mut store = Store::open_in_memory().unwrap();
        // Enforced in core, not in the UI form, so `bulwarkctl` can't route around it. An
        // unexplained suppression is the one thing that makes the audit trail worthless.
        for blank in ["", "   ", "\n\t "] {
            assert!(
                store
                    .suppress_rule("BLWK-SSH-001", blank, "vietanh")
                    .is_err(),
                "blank reason {blank:?} must be refused"
            );
        }
        assert!(store.list_suppressions().unwrap().is_empty());
        // ...and a refused suppression must not leave a phantom audit entry behind.
        assert!(store.suppression_audit_log(None, 100).unwrap().is_empty());
    }

    #[test]
    fn the_audit_trail_outlives_the_suppression_it_describes() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .suppress_rule(
                "BLWK-BANN-001",
                "no legal requirement on a personal laptop",
                "vietanh",
            )
            .unwrap();
        store
            .unsuppress_rule(
                "BLWK-BANN-001",
                "moved this host into the office rack",
                "vietanh",
            )
            .unwrap();

        // Current state is empty — the rule is live again.
        assert!(store.list_suppressions().unwrap().is_empty());
        assert!(store.suppressed_rule_ids().unwrap().is_empty());

        // But the *history* is intact, and that is the entire reason the two tables are separate.
        // A reviewer must still be able to ask "was this ever muted, by whom, and why?" and get a
        // real answer after the fact.
        let log = store.suppression_audit_log(None, 100).unwrap();
        assert_eq!(log.len(), 2, "both decisions must survive");
        assert_eq!(log[0].action, SuppressionAction::Unsuppressed);
        assert_eq!(log[0].reason, "moved this host into the office rack");
        assert_eq!(log[1].action, SuppressionAction::Suppressed);
        assert_eq!(log[1].reason, "no legal requirement on a personal laptop");
        assert!(log.iter().all(|e| e.actor == "vietanh"));
    }

    #[test]
    fn re_suppressing_supersedes_the_reason_without_losing_the_old_one() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .suppress_rule("BLWK-KERNEL-016", "docker sets ip_forward", "a")
            .unwrap();
        store
            .suppress_rule(
                "BLWK-KERNEL-016",
                "refined: docker bridge networking needs it",
                "b",
            )
            .unwrap();

        let active = store.list_suppressions().unwrap();
        assert_eq!(active.len(), 1, "still one suppression, not two");
        assert_eq!(
            active[0].reason,
            "refined: docker bridge networking needs it"
        );
        assert_eq!(active[0].created_by, "b");

        // The superseded justification is still on the record — people refine their reasoning, and
        // the earlier version is exactly what an auditor would want to compare against.
        let log = store
            .suppression_audit_log(Some("BLWK-KERNEL-016"), 100)
            .unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].reason, "docker sets ip_forward");
    }

    #[test]
    fn suppression_partitions_findings_but_never_discards_them() {
        let mut store = Store::open_in_memory().unwrap();
        store.persist_and_reconcile(&sample_scan()).unwrap();
        store
            .suppress_rule("BLWK-SSH-001", "this box has no sshd installed", "vietanh")
            .unwrap();

        // The finding is still in the database and still open — suppression is a decision about
        // *presentation*, not a delete, and definitely not a reason to stop checking.
        assert_eq!(store.open_findings().unwrap().len(), 1);

        let split = store.open_findings_split().unwrap();
        assert!(
            split.active.is_empty(),
            "nothing left for the user to act on"
        );
        assert_eq!(
            split.suppressed.len(),
            1,
            "but the accepted risk is still counted and still shown — '0 issues' and \
             '0 issues, 1 accepted' are different sentences"
        );
        assert_eq!(split.suppressed[0].rule_id, "BLWK-SSH-001");
    }

    #[test]
    fn lifting_a_suppression_that_isnt_there_is_an_error_not_a_silent_noop() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(store
            .unsuppress_rule("BLWK-NOPE-999", "cleaning up", "vietanh")
            .is_err());
        // And it must not have written an audit entry for something that never happened.
        assert!(store.suppression_audit_log(None, 100).unwrap().is_empty());
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

        let stored_first_seen: String = findings::table
            .filter(findings::rule_id.eq("BLWK-SSH-001"))
            .select(findings::first_seen)
            .first(&mut store.conn)
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
        // Each run's total_findings is the number of findings OPEN as of that run — the host's
        // real posture at that point in time. Here both findings are open at run 2 and the one is
        // open at run 1, so the counts are 2 and 1.
        assert_eq!(runs[0].total_findings, 2);
        assert_eq!(runs[1].total_findings, 1);
    }

    #[test]
    fn total_findings_counts_open_issues_not_what_a_narrow_run_re_observed() {
        // The History bug: a monitoring tick that evaluates only a subset of rules (unprivileged,
        // or a desktop-profile run that never loads the server rules) observes fewer findings than
        // are actually open, because reconciliation carries forward anything it can't disprove.
        // Recording the raw per-scan count made History flat-line and disagree with the Overview's
        // open count. total_findings must be the reconciled OPEN total.
        let mut store = Store::open_in_memory().unwrap();

        // Run 1 (broad): finds a server-profile finding and evaluates its rule.
        let mut broad = sample_scan();
        broad.findings[0].rule_id = "BLWK-LOG-002".into();
        broad.rules_evaluated = vec!["BLWK-LOG-002".into()];
        store.persist_and_reconcile(&broad).unwrap();

        // Run 2 (narrow): a desktop-profile tick that finds a DIFFERENT issue and does NOT evaluate
        // BLWK-LOG-002 at all (that rule wasn't loaded), so the LOG-002 finding carries forward.
        let mut narrow = sample_scan();
        narrow.id = Uuid::new_v4();
        narrow.findings[0].id = Uuid::new_v4();
        narrow.findings[0].rule_id = "BLWK-KERNEL-016".into();
        narrow.findings[0].scan_run_id = narrow.id;
        narrow.rules_evaluated = vec!["BLWK-KERNEL-016".into()];
        store.persist_and_reconcile(&narrow).unwrap();

        let runs = store.list_scan_runs(10).unwrap();
        assert_eq!(runs[0].id, narrow.id.to_string());
        // The narrow run's scan.findings.len() is 1, but TWO findings are open (LOG-002 carried
        // forward + the new KERNEL-016). History must show 2, matching what the Overview would.
        assert_eq!(
            runs[0].total_findings, 2,
            "History must reflect the open-issue count, not what the narrow tick happened to see"
        );
        assert_eq!(store.open_findings().unwrap().len(), 2);
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

        let rows: Vec<Finding> = findings::table
            .order(findings::rule_id.asc())
            .select(FindingRow::as_select())
            .load(&mut store.conn)
            .unwrap()
            .into_iter()
            .map(|r| r.try_into_finding().unwrap())
            .collect();

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
        let now = Utc::now().to_rfc3339();
        diesel::insert_into(findings::table)
            .values(FindingRow {
                id: "not-a-uuid".into(),
                scan_run_id,
                rule_id: "BLWK-TEST-001".into(),
                severity: "high".into(),
                title: "t".into(),
                explanation: "e".into(),
                fix_hint: "f".into(),
                context: "{}".into(),
                first_seen: now.clone(),
                last_seen: now,
                status: "open".into(),
            })
            .execute(&mut store.conn)
            .unwrap();

        assert!(store.open_findings().is_err());
    }

    /// Same as above but for the `scan_run_id` column specifically (a valid `id` with a
    /// malformed `scan_run_id`) — the two fields are parsed by separate `map_err` branches
    /// in `row_to_finding`, and struct-field evaluation order means a bad `id` alone never
    /// reaches the `scan_run_id` branch.
    #[test]
    fn a_row_with_a_malformed_scan_run_id_is_a_query_error_not_a_panic() {
        let mut store = Store::open_in_memory().unwrap();
        let now = Utc::now().to_rfc3339();
        // A scan_runs row whose own id is the same malformed string, so the FK on
        // findings.scan_run_id is satisfied without needing a well-formed UUID anywhere.
        diesel::insert_into(scan_runs::table)
            .values(ScanRunRow {
                id: "not-a-uuid-either".into(),
                started_at: now.clone(),
                finished_at: Some(now.clone()),
                host_fingerprint: "h".into(),
                rules_loaded: 0,
                rules_failed: 0,
                collectors_failed: 0,
                rule_load_errors: "[]".into(),
                collector_errors: "[]".into(),
                privileged_skipped: "[]".into(),
                total_findings: 0,
            })
            .execute(&mut store.conn)
            .unwrap();
        diesel::insert_into(findings::table)
            .values(FindingRow {
                id: Uuid::new_v4().to_string(),
                scan_run_id: "not-a-uuid-either".into(),
                rule_id: "BLWK-TEST-001".into(),
                severity: "high".into(),
                title: "t".into(),
                explanation: "e".into(),
                fix_hint: "f".into(),
                context: "{}".into(),
                first_seen: now.clone(),
                last_seen: now,
                status: "open".into(),
            })
            .execute(&mut store.conn)
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

    /// The bug this closes, reported from the running app: record a file-integrity baseline, and
    /// the "no file-integrity baseline yet" findings stayed on the dashboard forever — every
    /// later scan came back clean, but the reconciler could only ever *add* findings, never close
    /// one. A fixed issue must actually disappear.
    #[test]
    fn a_fixed_issue_is_resolved_once_its_rule_runs_clean() {
        let mut store = Store::open_in_memory().unwrap();

        // Scan 1: BLWK-FIM-003 fires (no baseline recorded yet).
        let mut first = sample_scan();
        first.findings[0].rule_id = "BLWK-FIM-003".into();
        first.rules_evaluated = vec!["BLWK-FIM-003".into()];
        store.persist_and_reconcile(&first).unwrap();
        assert_eq!(store.open_findings().unwrap().len(), 1);

        // Scan 2: the user recorded a baseline. The rule ran (it's in rules_evaluated) and no
        // longer fires, so the issue is demonstrably fixed and must be closed.
        let mut second = sample_scan();
        second.findings.clear();
        second.rules_evaluated = vec!["BLWK-FIM-003".into()];
        store.persist_and_reconcile(&second).unwrap();
        assert!(
            store.open_findings().unwrap().is_empty(),
            "a rule that ran and no longer fires must resolve its finding, not leave it open forever"
        );
    }

    /// The other half of the same contract, and the reason auto-resolution was avoided before:
    /// absence must NOT be read as "fixed" when the check never actually ran. A privileged
    /// collector skipped during an unprivileged tick must leave its findings untouched.
    #[test]
    fn a_finding_is_not_resolved_when_its_rule_never_ran() {
        let mut store = Store::open_in_memory().unwrap();

        let mut first = sample_scan();
        first.findings[0].rule_id = "BLWK-PRIV-001".into();
        first.rules_evaluated = vec!["BLWK-PRIV-001".into()];
        store.persist_and_reconcile(&first).unwrap();
        assert_eq!(store.open_findings().unwrap().len(), 1);

        // An unprivileged tick: the sudoers collector was skipped, so BLWK-PRIV-001 never ran.
        // It produced no finding — but that proves nothing, so the row must stay open.
        let mut second = sample_scan();
        second.findings.clear();
        second.rules_evaluated = vec![]; // did not run
        second.privileged_collectors_skipped = vec!["sudoers".into()];
        store.persist_and_reconcile(&second).unwrap();
        assert_eq!(
            store.open_findings().unwrap().len(),
            1,
            "a skipped check must never be mistaken for a passing one"
        );
    }

    /// A list-shaped rule (one finding per watched file) must resolve only the rows that are
    /// actually gone — fixing one file must not silently close the findings for the others.
    #[test]
    fn resolving_is_per_row_for_a_list_shaped_rule() {
        let mut store = Store::open_in_memory().unwrap();
        let now = Utc::now();

        let row = |path: &str| {
            let mut ctx = crate::models::Fact::new();
            ctx.insert("path".into(), serde_json::Value::String(path.into()));
            Finding {
                id: Uuid::new_v4(),
                rule_id: "BLWK-FIM-003".into(),
                severity: Severity::Info,
                title: format!("no baseline: {path}"),
                explanation: "e".into(),
                fix_hint: "f".into(),
                context: ctx,
                first_seen: now,
                last_seen: now,
                status: FindingStatus::Open,
                scan_run_id: Uuid::new_v4(),
            }
        };

        let mut first = sample_scan();
        first.findings = vec![row("/etc/passwd"), row("/etc/crontab")];
        // The findings table has an FK onto scan_runs — a finding must belong to its own run.
        first
            .findings
            .iter_mut()
            .for_each(|f| f.scan_run_id = first.id);
        first.rules_evaluated = vec!["BLWK-FIM-003".into()];
        store.persist_and_reconcile(&first).unwrap();
        assert_eq!(store.open_findings().unwrap().len(), 2);

        // Only /etc/crontab still lacks a baseline now.
        let mut second = sample_scan();
        second.findings = vec![row("/etc/crontab")];
        second
            .findings
            .iter_mut()
            .for_each(|f| f.scan_run_id = second.id);
        second.rules_evaluated = vec!["BLWK-FIM-003".into()];
        store.persist_and_reconcile(&second).unwrap();

        let open = store.open_findings().unwrap();
        assert_eq!(open.len(), 1, "only the fixed row should close");
        assert_eq!(
            open[0].context.get("path").unwrap(),
            &serde_json::Value::String("/etc/crontab".into())
        );
    }

    #[test]
    fn ai_scan_round_trips_through_the_store() {
        use crate::ai_scan::{AiFinding, AiScanReport};
        let tmp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&tmp.path().join("ai.db")).unwrap();

        let report = AiScanReport {
            id: uuid::Uuid::new_v4(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            host_fingerprint: "host/6.8".into(),
            workspaces_scanned: vec!["/home/u/proj".into()],
            artifacts_scanned: 5,
            workspaces_capped: false,
            cancelled: false,
            errors: vec![],
            findings: vec![AiFinding {
                id: uuid::Uuid::new_v4(),
                rule_id: "BLWK-AI-001".into(),
                severity: Severity::Critical,
                tool: "Claude Code".into(),
                title: "Anthropic API key exposed in AI context".into(),
                explanation: "e".into(),
                fix_hint: "f".into(),
                file: "/home/u/proj/CLAUDE.md".into(),
                line: Some(12),
                evidence: "Anthropic API key: sk-a…AA".into(),
                references: vec!["ATTACK-T1552.001".into()],
                redactable: true,
            }],
        };
        store.persist_ai_scan(&report).unwrap();

        let snap = store
            .latest_ai_scan()
            .unwrap()
            .expect("a scan was persisted");
        assert_eq!(snap.artifacts_scanned, 5);
        assert_eq!(snap.findings.len(), 1);
        assert_eq!(snap.findings[0].rule_id, "BLWK-AI-001");
        assert!(snap.findings[0].redactable);
        assert_eq!(snap.findings[0].line, Some(12));

        // Latest-run-wins: a second, empty scan supersedes the first (a redacted secret is
        // simply gone, not lingering as an open row).
        let empty = AiScanReport {
            id: uuid::Uuid::new_v4(),
            started_at: Utc::now() + chrono::Duration::seconds(1),
            findings: vec![],
            ..report.clone()
        };
        store.persist_ai_scan(&empty).unwrap();
        assert_eq!(store.latest_ai_scan().unwrap().unwrap().findings.len(), 0);
    }

    #[test]
    fn removing_redacted_findings_drops_only_secrets_for_those_files() {
        use crate::ai_scan::{AiFinding, AiScanReport};
        let tmp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&tmp.path().join("ai.db")).unwrap();

        let mk = |file: &str, rule: &str, redactable: bool| AiFinding {
            id: uuid::Uuid::new_v4(),
            rule_id: rule.into(),
            severity: Severity::Critical,
            tool: "Claude Code".into(),
            title: "t".into(),
            explanation: "e".into(),
            fix_hint: "f".into(),
            file: file.into(),
            line: None,
            evidence: "x".into(),
            references: vec![],
            redactable,
        };
        let report = AiScanReport {
            id: uuid::Uuid::new_v4(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            host_fingerprint: "h".into(),
            workspaces_scanned: vec![],
            artifacts_scanned: 3,
            workspaces_capped: false,
            cancelled: false,
            errors: vec![],
            findings: vec![
                mk("/home/u/a.md", "BLWK-AI-001", true), // secret, will be redacted
                mk("/home/u/a.md", "BLWK-AI-002", false), // non-secret in the SAME file — must stay
                mk("/home/u/b.md", "BLWK-AI-001", true), // secret in a DIFFERENT file — must stay
            ],
        };
        store.persist_ai_scan(&report).unwrap();

        let removed = store
            .remove_redacted_ai_findings(&["/home/u/a.md".to_string()])
            .unwrap();
        assert_eq!(
            removed, 1,
            "only the one redactable finding in a.md is removed"
        );

        let remaining = store.latest_ai_scan().unwrap().unwrap().findings;
        assert_eq!(remaining.len(), 2);
        // The non-secret finding in the redacted file survives (redaction didn't address it)...
        assert!(remaining
            .iter()
            .any(|f| f.file == "/home/u/a.md" && f.rule_id == "BLWK-AI-002"));
        // ...and the secret in the untouched file survives (it wasn't redacted).
        assert!(remaining
            .iter()
            .any(|f| f.file == "/home/u/b.md" && f.rule_id == "BLWK-AI-001"));
    }

    #[test]
    fn agent_scan_prunes_earlier_runs_detail_but_keeps_summaries() {
        use crate::ai_scan::{AiFinding, AiScanReport};
        let tmp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&tmp.path().join("ai.db")).unwrap();

        let mk = |n: usize, secs: i64| AiScanReport {
            id: uuid::Uuid::new_v4(),
            started_at: Utc::now() + chrono::Duration::seconds(secs),
            finished_at: Some(Utc::now()),
            host_fingerprint: "h".into(),
            workspaces_scanned: vec![],
            artifacts_scanned: n,
            workspaces_capped: false,
            cancelled: false,
            errors: vec![],
            findings: (0..n)
                .map(|i| AiFinding {
                    id: uuid::Uuid::new_v4(),
                    rule_id: "BLWK-AI-001".into(),
                    severity: Severity::Critical,
                    tool: "t".into(),
                    title: "x".into(),
                    explanation: "e".into(),
                    fix_hint: "f".into(),
                    file: format!("/p/{i}"),
                    line: None,
                    evidence: String::new(),
                    references: vec![],
                    redactable: false,
                })
                .collect(),
        };

        store.persist_ai_scan(&mk(5, 0)).unwrap();
        store.persist_ai_scan(&mk(3, 1)).unwrap();

        // The detail table holds only the latest run's rows (3), never the accumulated sum (8) —
        // this is the bloat fix that keeps the stored data from drifting away from what the tabs
        // show (a real machine had thousands of dead rows behind a 243-finding display).
        let detail_rows: i64 = ai_findings::table
            .count()
            .get_result(&mut store.conn)
            .unwrap();
        assert_eq!(
            detail_rows, 3,
            "only the latest run's findings detail is retained"
        );

        // Both run summaries survive — they carry total_findings for a findings-over-time view.
        let run_rows: i64 = ai_scan_runs::table
            .count()
            .get_result(&mut store.conn)
            .unwrap();
        assert_eq!(
            run_rows, 2,
            "per-run summaries are kept for history/analytics"
        );

        assert_eq!(store.latest_ai_scan().unwrap().unwrap().findings.len(), 3);
    }

    #[test]
    fn migrations_apply_cleanly_to_a_fresh_database() {
        // Catches a malformed migration (bad SQL, a missing table) at test time rather than on a
        // user's machine at startup.
        let tmp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&tmp.path().join("fresh.db")).unwrap();
        assert!(
            store.is_schema_current().unwrap(),
            "a freshly opened database must have every migration applied"
        );
        // Every table the code queries must actually exist after migrating.
        assert_eq!(store.count_scan_runs().unwrap(), 0);
        assert_eq!(store.count_log_scan_runs().unwrap(), 0);
        assert!(store.latest_ai_scan().unwrap().is_none());
        assert!(store.get_setting("anything").unwrap().is_none());
    }

    #[test]
    fn opening_an_already_migrated_db_twice_is_a_no_op() {
        // The path every user hits on every launch after the first: migrations must not re-run or
        // error against a database that is already current, and the data must survive.
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("repeat.db");
        {
            let mut store = Store::open(&db_path).unwrap();
            store.persist_and_reconcile(&sample_scan()).unwrap();
        }
        let mut store = Store::open(&db_path).unwrap();
        assert!(store.is_schema_current().unwrap());
        assert_eq!(store.open_findings().unwrap().len(), 1, "data must survive");
    }

    /// A database written by a pre-Diesel build has Bulwark's tables but none of Diesel's
    /// migration bookkeeping. Rather than attempt a bespoke cross-framework migration, it is moved
    /// aside and a fresh database created — findings are a cache of host state and are rebuilt by
    /// the next scan. The old file must be *kept*, not deleted: it is still the user's data.
    #[test]
    fn a_pre_orm_database_is_moved_aside_and_replaced_with_a_fresh_one() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("legacy.db");
        {
            let mut conn = SqliteConnection::establish(db_path.to_str().unwrap()).unwrap();
            diesel::sql_query(
                "CREATE TABLE findings (
                    id TEXT PRIMARY KEY, scan_run_id TEXT NOT NULL, rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL, title TEXT NOT NULL, explanation TEXT NOT NULL,
                    fix_hint TEXT NOT NULL, context TEXT NOT NULL, first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL, status TEXT NOT NULL
                )",
            )
            .execute(&mut conn)
            .unwrap();
        }

        let mut store = Store::open(&db_path).unwrap();

        assert!(
            store.is_schema_current().unwrap(),
            "the replacement database must be fully migrated"
        );
        assert_eq!(store.count_scan_runs().unwrap(), 0);
        assert!(
            db_path.with_extension("db.pre-orm.bak").exists(),
            "the old database must be preserved, not silently deleted — it is the user's data"
        );
    }

    #[test]
    fn missing_setting_is_none_not_an_error() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(store.get_setting("nope").unwrap(), None);
    }

    #[test]
    fn setting_round_trips() {
        let mut store = Store::open_in_memory().unwrap();
        store.set_setting("realtime_av_enabled", "true").unwrap();
        assert_eq!(
            store.get_setting("realtime_av_enabled").unwrap(),
            Some("true".to_string())
        );
    }

    #[test]
    fn setting_a_key_twice_overwrites_rather_than_erroring() {
        let mut store = Store::open_in_memory().unwrap();
        store.set_setting("k", "first").unwrap();
        store.set_setting("k", "second").unwrap();
        assert_eq!(store.get_setting("k").unwrap(), Some("second".to_string()));
    }

    fn sample_log_scan(group_key: &str) -> crate::logs::LogScanRun {
        let now = Utc::now();
        crate::logs::LogScanRun {
            id: Uuid::new_v4(),
            started_at: now,
            finished_at: Some(now),
            host_fingerprint: "test-host/6.8.0".into(),
            events_read: 8,
            events_decoded: 8,
            decoders_loaded: 4,
            rules_loaded: 7,
            decoder_load_errors: vec![],
            rule_load_errors: vec![],
            read_errors: vec![],
            rule_eval_errors: vec![],
            findings: vec![crate::logs::LogFinding {
                id: Uuid::new_v4(),
                rule_id: "BLWK-LOG-SSH-001".into(),
                severity: Severity::High,
                category: "ssh-remote-access".into(),
                title: "SSH brute-force".into(),
                explanation: "e".into(),
                fix_hint: "f".into(),
                group_key: group_key.into(),
                match_count: 8,
                context: crate::models::Fact::new(),
                observed_at: now,
                references: vec!["ATTACK-T1110".into()],
            }],
        }
    }

    #[test]
    fn persist_log_scan_reconciles_same_rule_and_key_instead_of_duplicating() {
        let mut store = Store::open_in_memory().unwrap();

        // First sighting: newly appeared.
        let newly = store
            .persist_log_scan(&sample_log_scan("203.0.113.7"))
            .unwrap();
        assert_eq!(newly.len(), 1);
        assert_eq!(store.count_log_findings().unwrap(), 1);

        // Same (rule_id, group_key) again: reconciled in place, nothing "newly appeared".
        let newly = store
            .persist_log_scan(&sample_log_scan("203.0.113.7"))
            .unwrap();
        assert!(newly.is_empty());
        assert_eq!(store.count_log_findings().unwrap(), 1, "must not duplicate");
        assert_eq!(store.count_log_scan_runs().unwrap(), 2);

        // A different source IP is a genuinely different alert.
        let newly = store
            .persist_log_scan(&sample_log_scan("198.51.100.9"))
            .unwrap();
        assert_eq!(newly.len(), 1);
        assert_eq!(store.count_log_findings().unwrap(), 2);

        // occurrences bumped for the reconciled key (seen twice), 1 for the new key.
        let occ: i64 = log_findings::table
            .filter(log_findings::group_key.eq("203.0.113.7"))
            .select(log_findings::occurrences)
            .first(&mut store.conn)
            .unwrap();
        assert_eq!(occ, 2);
    }
}
