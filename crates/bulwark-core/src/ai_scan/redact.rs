//! Opt-in secret redaction. Bulwark never rewrites an AI context file on its own — finding a
//! secret and removing it are two deliberate, separate acts (the same stance file-integrity
//! baselining takes: a destructive-ish action stays an explicit user choice, never automatic).
//!
//! The flow is dry-run first: [`redact_paths`] with `apply = false` reports exactly which files
//! would change and how many secrets each holds, changing nothing. With `apply = true` it writes
//! a `0600` backup of every file it touches *before* overwriting, preserves the original file's
//! permissions on the rewritten copy, and replaces each high-confidence secret with an inert
//! placeholder. Only high-confidence provider secrets are redacted — the fuzzy `KEY=value`
//! heuristic is report-only, because blindly rewriting a value that merely *looked* like a
//! secret could corrupt a legitimate config.

use super::secrets;
use std::path::{Path, PathBuf};

/// Files larger than this are skipped by redaction — a multi-hundred-MB transcript rewrite is
/// not something to do silently, and the same cap the scanner uses keeps behavior consistent.
const MAX_REDACT_BYTES: u64 = 8 * 1024 * 1024;

/// One file the redaction pass considered. `secrets_redacted` is how many high-confidence
/// secrets were found (and, if `applied`, replaced). `backup_path` is set only when a backup was
/// actually written (`apply = true` and at least one secret present).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RedactionEntry {
    pub path: String,
    pub secrets_redacted: usize,
    pub backup_path: Option<String>,
    pub applied: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactionReport {
    pub dry_run: bool,
    pub entries: Vec<RedactionEntry>,
    pub total_secrets: usize,
    pub errors: Vec<String>,
}

/// Redacts (or, in dry-run, previews redacting) every high-confidence secret in `paths`.
/// `backup_dir` receives a timestamp-free, path-derived `.bak` copy of each modified file with
/// `0600` permissions before it's overwritten; it's created if absent. In dry-run mode nothing
/// is read-only-violated: files are read but never written and no backups are made.
pub fn redact_paths(paths: &[PathBuf], apply: bool, backup_dir: &Path) -> RedactionReport {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut total = 0usize;

    for path in paths {
        match redact_one(path, apply, backup_dir) {
            Ok(Some(entry)) => {
                total += entry.secrets_redacted;
                entries.push(entry);
            }
            Ok(None) => {}
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }

    RedactionReport {
        dry_run: !apply,
        entries,
        total_secrets: total,
        errors,
    }
}

fn redact_one(
    path: &Path,
    apply: bool,
    backup_dir: &Path,
) -> anyhow::Result<Option<RedactionEntry>> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Ok(None);
    }
    if meta.len() > MAX_REDACT_BYTES {
        anyhow::bail!(
            "file is larger than the {}MB redaction limit — redact it by hand",
            MAX_REDACT_BYTES / 1024 / 1024
        );
    }

    // A non-UTF-8 file (e.g. a SQLite transcript store) isn't safe to rewrite as text; skip it
    // rather than risk corrupting a binary.
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    let (redacted, count) = secrets::redact_text(&content);
    if count == 0 {
        return Ok(None);
    }

    if !apply {
        return Ok(Some(RedactionEntry {
            path: path.display().to_string(),
            secrets_redacted: count,
            backup_path: None,
            applied: false,
        }));
    }

    let backup_path = write_backup(path, &content, backup_dir)?;
    write_preserving_permissions(path, &redacted, &meta)?;

    Ok(Some(RedactionEntry {
        path: path.display().to_string(),
        secrets_redacted: count,
        backup_path: Some(backup_path.display().to_string()),
        applied: true,
    }))
}

/// Writes the pre-redaction content to `backup_dir` under a filename derived from the source
/// path (its components joined by `_`), suffixed `.bak`, with `0600` permissions so the backup
/// of a secret file isn't itself a wider exposure than the original. Collisions get a numeric
/// suffix rather than overwriting an earlier backup.
fn write_backup(path: &Path, content: &str, backup_dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(backup_dir)?;
    let stem = path
        .to_string_lossy()
        .trim_start_matches('/')
        .replace(['/', '\\'], "_");
    let mut candidate = backup_dir.join(format!("{stem}.bak"));
    let mut n = 1;
    while candidate.exists() {
        candidate = backup_dir.join(format!("{stem}.{n}.bak"));
        n += 1;
    }
    std::fs::write(&candidate, content)?;
    set_owner_only(&candidate)?;
    Ok(candidate)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Overwrites `path` with `content`, restoring the original file's permission bits afterward so
/// redaction never quietly loosens (or tightens) a file's mode.
fn write_preserving_permissions(
    path: &Path,
    content: &str,
    original: &std::fs::Metadata,
) -> anyhow::Result<()> {
    std::fs::write(path, content)?;
    std::fs::set_permissions(path, original.permissions())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anthropic_key() -> String {
        format!("sk-ant-api03-{}AA", "a".repeat(93))
    }

    #[test]
    fn dry_run_reports_without_changing_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("CLAUDE.md");
        let original = format!("my key is {}\n", anthropic_key());
        std::fs::write(&file, &original).unwrap();

        let report = redact_paths(
            std::slice::from_ref(&file),
            false,
            &dir.path().join("backups"),
        );
        assert!(report.dry_run);
        assert_eq!(report.total_secrets, 1);
        assert_eq!(report.entries.len(), 1);
        assert!(!report.entries[0].applied);
        assert!(report.entries[0].backup_path.is_none());
        // File is untouched.
        assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
        // No backup directory work happened.
        assert!(!dir.path().join("backups").exists());
    }

    #[test]
    fn apply_redacts_backs_up_and_preserves_perms() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("notes.md");
        let key = anthropic_key();
        std::fs::write(&file, format!("token: {key}\nkeep this line\n")).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        let backups = dir.path().join("backups");
        let report = redact_paths(std::slice::from_ref(&file), true, &backups);
        assert_eq!(report.total_secrets, 1);
        assert!(report.entries[0].applied);

        let after = std::fs::read_to_string(&file).unwrap();
        assert!(!after.contains(&key), "secret must be gone from the file");
        assert!(
            after.contains("keep this line"),
            "other content is preserved"
        );
        assert!(after.contains(secrets::REDACTION_PLACEHOLDER));

        // The backup holds the original secret and is 0600.
        let backup = report.entries[0].backup_path.as_ref().unwrap();
        let backup_content = std::fs::read_to_string(backup).unwrap();
        assert!(backup_content.contains(&key));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let bmode = std::fs::metadata(backup).unwrap().permissions().mode() & 0o777;
            assert_eq!(bmode, 0o600, "backup of a secret must be owner-only");
            let fmode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(fmode, 0o640, "original file mode must be preserved");
        }
    }

    #[test]
    fn a_clean_file_produces_no_entry() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("clean.md");
        std::fs::write(&file, "no secrets here, just prose\n").unwrap();
        let report = redact_paths(&[file], true, &dir.path().join("b"));
        assert!(report.entries.is_empty());
        assert_eq!(report.total_secrets, 0);
    }

    #[test]
    fn re_running_apply_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.md");
        std::fs::write(&file, format!("{}\n", anthropic_key())).unwrap();
        let backups = dir.path().join("b");
        let first = redact_paths(std::slice::from_ref(&file), true, &backups);
        assert_eq!(first.total_secrets, 1);
        let second = redact_paths(&[file], true, &backups);
        assert_eq!(
            second.total_secrets, 0,
            "a redacted file has nothing left to redact"
        );
    }
}
