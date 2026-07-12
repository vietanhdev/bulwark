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
    // `symlink_metadata`, not `metadata`: the latter follows symlinks, and both the read below
    // and the rewrite in `write_preserving_permissions` would then act on the *target*. Because
    // redaction rewrites files discovered by walking $HOME, a symlink planted in a scanned
    // directory (e.g. one that syncs from elsewhere) could otherwise redirect the overwrite onto
    // an arbitrary file the user can write. A regular file is the only safe thing to rewrite in
    // place; anything else is reported as skipped rather than silently followed.
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("path is a symlink; refusing to rewrite through it");
    }
    if !meta.is_file() {
        return Ok(None);
    }

    // Open once with O_NOFOLLOW and do everything (size check, read, permission capture) against
    // that single file descriptor. Re-opening the path by name for the read — after the
    // symlink_metadata check above — would leave a TOCTOU window in which a symlink raced into the
    // path could redirect the read; O_NOFOLLOW makes the open itself fail if that happens.
    let mut file = open_no_follow(path)?;
    let meta = file.metadata()?;
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
    // rather than risk corrupting a binary. Read is capped by the size check plus the take().
    let content = {
        use std::io::Read;
        let mut bytes = Vec::new();
        if file
            .by_ref()
            .take(MAX_REDACT_BYTES)
            .read_to_end(&mut bytes)
            .is_err()
        {
            return Ok(None);
        }
        match String::from_utf8(bytes) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        }
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
    // The backup holds the ORIGINAL, un-redacted secret, so its directory is the most sensitive
    // thing this feature writes. Lock it to owner-only (0700) rather than trust the umask — the
    // per-file 0600 below already covers each backup, this covers the directory listing too.
    set_dir_owner_only(backup_dir);
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
    write_owner_only(&candidate, content)?;
    Ok(candidate)
}

/// Writes `content` to a freshly-created file that is owner-only (0600) from the moment it exists,
/// rather than creating it under the umask (typically 0644) and tightening afterward — the backup
/// holds the original, un-redacted secret, so it must never have even a brief world-readable
/// window. `create_new` also refuses to write through a pre-existing name/symlink.
#[cfg(unix)]
fn write_owner_only(path: &Path, content: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content)?;
    Ok(())
}

/// Best-effort `0700` on the backup directory. Silent on failure (non-Unix, exotic FS) — it's a
/// hardening step layered on top of the already-`0700` parent data dir, not a correctness gate.
#[cfg(unix)]
fn set_dir_owner_only(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_owner_only(_dir: &Path) {}

/// Replaces `path`'s contents with `content` atomically — write a sibling temp file, give it the
/// original's permission bits, then `rename` it over the target. Atomic because `rename(2)` on the
/// same directory is: a reader ever sees either the old file or the fully-redacted new one, never a
/// half-truncated file, and a crash mid-write leaves the original intact (the backup written just
/// before is a second safety net). Renaming also *replaces* the directory entry rather than writing
/// through it, so this never follows a symlink even if one raced in after the `symlink_metadata`
/// check above.
fn write_preserving_permissions(
    path: &Path,
    content: &str,
    original: &std::fs::Metadata,
) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path has no file name"))?
        .to_string_lossy();
    let tmp = dir.join(format!(".{file_name}.bulwark-redact.tmp"));

    // Clean up any leftover temp from a previously interrupted run, then create the new one with
    // O_EXCL | O_NOFOLLOW: in a group/world-writable scan directory another user could otherwise
    // race a symlink into this temp name between remove and open and redirect our write through it.
    // O_EXCL fails if the name already exists (their planted symlink), O_NOFOLLOW fails if it's a
    // symlink — either way we never write through an attacker's link. Everything is removed on the
    // error paths so a failure can't leak the temp.
    let _ = std::fs::remove_file(&tmp);
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = create_temp_exclusive(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.set_permissions(original.permissions())?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Opens `path` for reading, failing (rather than following) if it is a symlink.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Creates `tmp` for writing, failing if it already exists or is a symlink (`O_EXCL | O_NOFOLLOW`).
#[cfg(unix)]
fn create_temp_exclusive(tmp: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(tmp)
}

#[cfg(not(unix))]
fn create_temp_exclusive(tmp: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
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

    #[cfg(unix)]
    #[test]
    fn a_symlinked_key_file_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        // A real secret-bearing file the attacker wants overwritten, out of the intended scope.
        let target = dir.path().join("real-secret.txt");
        let original = format!("token {}\n", anthropic_key());
        std::fs::write(&target, &original).unwrap();
        // A symlink named like a scanned artifact, pointing at that target.
        let link = dir.path().join("CLAUDE.md");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let report = redact_paths(std::slice::from_ref(&link), true, &dir.path().join("b"));
        // The symlink is reported as an error, nothing is redacted, and the target is untouched.
        assert!(report.entries.is_empty());
        assert!(report.errors.iter().any(|e| e.contains("symlink")));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
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
