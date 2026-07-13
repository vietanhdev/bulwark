-- Reverses the rule-suppression tables. The index goes with its table, so dropping the tables is
-- enough, but it is named explicitly for symmetry with the init migration.
DROP INDEX IF EXISTS idx_rule_suppression_events_rule_at;
DROP TABLE IF EXISTS rule_suppression_events;
DROP TABLE IF EXISTS rule_suppressions;
