-- Reverses the initial schema. Order matters: the child tables carry foreign keys onto the run
-- tables, so they go first.
DROP INDEX IF EXISTS idx_ai_findings_run;
DROP TABLE IF EXISTS ai_findings;
DROP TABLE IF EXISTS ai_scan_runs;

DROP INDEX IF EXISTS idx_log_findings_scan;
DROP INDEX IF EXISTS idx_log_findings_rule_key;
DROP TABLE IF EXISTS log_findings;
DROP TABLE IF EXISTS log_scan_runs;

DROP TABLE IF EXISTS settings;

DROP INDEX IF EXISTS idx_findings_scan_run;
DROP INDEX IF EXISTS idx_findings_rule_status;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scan_runs;
