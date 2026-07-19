-- Reverses the rules_evaluated column. SQLite has supported DROP COLUMN since 3.35 (2021), and
-- this crate vendors its own SQLite via libsqlite3-sys, so the version is ours to rely on.
--
-- Note that this is genuinely lossy: the dropped set cannot be reconstructed, so a database taken
-- down and up again scores as "not assessed" until the next scan. That is the correct outcome
-- rather than a caveat — see up.sql.
ALTER TABLE scan_runs DROP COLUMN rules_evaluated;
