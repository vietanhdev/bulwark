-- Ignoring one finding rather than a whole type: a rule (`rule_id`) at one place (`location` — the
-- file, port or other identity `findings::finding_location` derives). Same accountability as a
-- type-level suppression: a reason is required and every change lands in the audit log, which
-- gains a nullable `location` (NULL = the whole rule, as every earlier event was).
CREATE TABLE finding_ignores (
    rule_id    TEXT NOT NULL,
    location   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY (rule_id, location)
);
ALTER TABLE rule_suppression_events ADD COLUMN location TEXT;
