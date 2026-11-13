-- Reverses the severity_counts column (SQLite 3.35+, and this crate vendors its own SQLite).
-- Lossy by nature: the split is not recoverable, so runs read as "not recorded" after an up again.
ALTER TABLE scan_runs DROP COLUMN severity_counts;
