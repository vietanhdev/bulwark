-- Bulwark's initial schema.
--
-- This is a clean baseline, not a replay of history. The four hand-rolled `rusqlite_migration`
-- steps that preceded it (findings, settings, log tables, AI tables) were collapsed into one
-- migration when the store moved to Diesel, which is only safe because Bulwark had not shipped a
-- database anyone needed to keep. From here on the rule is the usual one, and it is not
-- negotiable: **migrations are append-only**. A database already stamped with a migration will
-- never re-run it, so editing one silently splits users into two different schemas depending on
-- when they first installed. Add a new migration directory instead.
--
-- Three separate "run + findings" table pairs, deliberately, because the three engines have
-- genuinely different semantics rather than merely different data:
--
--   * config scans   — state-shaped. A finding persists until the thing is fixed; identity is
--                      (rule_id + a context subset), and reconciliation updates in place.
--   * log scans      — event-shaped. Alerts recur; identity is (rule_id + group_key) and repeats
--                      bump an occurrence counter rather than duplicating.
--   * agent scans    — snapshot-shaped. Latest run wins outright: a secret you have since
--                      redacted should simply be absent next time, not linger as an "open" row.
--
-- Collapsing them into one table would mean picking one of those three reconciliation models and
-- forcing the other two to lie about themselves.

CREATE TABLE scan_runs (
    id                 TEXT PRIMARY KEY NOT NULL,
    started_at         TEXT NOT NULL,
    finished_at        TEXT,
    host_fingerprint   TEXT NOT NULL,
    rules_loaded       BIGINT NOT NULL,
    rules_failed       BIGINT NOT NULL,
    collectors_failed  BIGINT NOT NULL,
    rule_load_errors   TEXT NOT NULL,
    collector_errors   TEXT NOT NULL,
    privileged_skipped TEXT NOT NULL,
    total_findings     BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE findings (
    id          TEXT PRIMARY KEY NOT NULL,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    explanation TEXT NOT NULL,
    fix_hint    TEXT NOT NULL,
    context     TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    status      TEXT NOT NULL
);

CREATE INDEX idx_findings_rule_status ON findings(rule_id, status);
CREATE INDEX idx_findings_scan_run ON findings(scan_run_id);

-- Small key/value store for persisted preferences (monitoring interval, real-time AV toggle and
-- watched folders, agent-scan roots). Not worth a table per setting.
CREATE TABLE settings (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE log_scan_runs (
    id                  TEXT PRIMARY KEY NOT NULL,
    started_at          TEXT NOT NULL,
    finished_at         TEXT,
    host_fingerprint    TEXT NOT NULL,
    events_read         BIGINT NOT NULL,
    events_decoded      BIGINT NOT NULL,
    decoders_loaded     BIGINT NOT NULL,
    rules_loaded        BIGINT NOT NULL,
    total_findings      BIGINT NOT NULL,
    decoder_load_errors TEXT NOT NULL,
    rule_load_errors    TEXT NOT NULL,
    read_errors         TEXT NOT NULL,
    rule_eval_errors    TEXT NOT NULL
);

CREATE TABLE log_findings (
    id              TEXT PRIMARY KEY NOT NULL,
    log_scan_run_id TEXT NOT NULL REFERENCES log_scan_runs(id),
    rule_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    category        TEXT NOT NULL,
    title           TEXT NOT NULL,
    explanation     TEXT NOT NULL,
    fix_hint        TEXT NOT NULL,
    group_key       TEXT NOT NULL,
    match_count     BIGINT NOT NULL,
    context         TEXT NOT NULL,
    refs            TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    occurrences     BIGINT NOT NULL DEFAULT 1
);

CREATE INDEX idx_log_findings_rule_key ON log_findings(rule_id, group_key);
CREATE INDEX idx_log_findings_scan ON log_findings(log_scan_run_id);

CREATE TABLE ai_scan_runs (
    id                 TEXT PRIMARY KEY NOT NULL,
    started_at         TEXT NOT NULL,
    finished_at        TEXT,
    host_fingerprint   TEXT NOT NULL,
    workspaces_scanned TEXT NOT NULL,
    artifacts_scanned  BIGINT NOT NULL,
    total_findings     BIGINT NOT NULL,
    workspaces_capped  BOOL NOT NULL,
    scan_errors        TEXT NOT NULL
);

CREATE TABLE ai_findings (
    id             TEXT PRIMARY KEY NOT NULL,
    ai_scan_run_id TEXT NOT NULL REFERENCES ai_scan_runs(id),
    rule_id        TEXT NOT NULL,
    severity       TEXT NOT NULL,
    tool           TEXT NOT NULL,
    title          TEXT NOT NULL,
    explanation    TEXT NOT NULL,
    fix_hint       TEXT NOT NULL,
    file           TEXT NOT NULL,
    line           BIGINT,
    evidence       TEXT NOT NULL,
    refs           TEXT NOT NULL,
    redactable     BOOL NOT NULL
);

CREATE INDEX idx_ai_findings_run ON ai_findings(ai_scan_run_id);
