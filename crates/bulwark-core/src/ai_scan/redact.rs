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

    // Open once with O_NOFOLLOW (the symlink_metadata check above closes the by-name TOCTOU: a
    // symlink raced into the path makes this open fail rather than redirect it).
    let file = open_no_follow(path)?;
    let fmeta = file.metadata()?;
    if !fmeta.is_file() {
        return Ok(None);
    }

    // Dry-run: stream the file counting redactable secrets, writing nothing.
    if !apply {
        let count = count_redactions(std::io::BufReader::new(file))?;
        return Ok((count > 0).then(|| RedactionEntry {
            path: path.display().to_string(),
            secrets_redacted: count,
            backup_path: None,
            applied: false,
        }));
    }

    // Apply, streaming. AI session transcripts run to tens of megabytes, so the whole file is never
    // held in memory: we read one line at a time, write it verbatim to the backup and its redacted
    // form to a sibling temp file, then swap the temp in atomically. Line-oriented is exactly right
    // for the `.jsonl` transcripts this targets, and a secret never spans a newline, so nothing is
    // missed at a boundary. A non-UTF-8 line is passed through unchanged rather than corrupted.
    std::fs::create_dir_all(backup_dir)?;
    // The backup holds the ORIGINAL, un-redacted secret — lock its directory to owner-only.
    set_dir_owner_only(backup_dir);
    let backup_path = backup_target(path, backup_dir);

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path has no file name"))?
        .to_string_lossy();
    let tmp = dir.join(format!(".{file_name}.bulwark-redact.tmp"));
    let _ = std::fs::remove_file(&tmp);

    let cleanup = || {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&backup_path);
    };

    let count = match stream_to_backup_and_temp(file, &backup_path, &tmp) {
        Ok(n) => n,
        Err(e) => {
            cleanup();
            return Err(e);
        }
    };

    if count == 0 {
        // Flagged, but nothing high-confidence to rewrite — leave the original untouched.
        cleanup();
        return Ok(None);
    }

    // Preserve the original's permission bits on the redacted copy, then swap it in atomically.
    if let Err(e) = std::fs::set_permissions(&tmp, fmeta.permissions()) {
        cleanup();
        return Err(e.into());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        cleanup();
        return Err(e.into());
    }

    Ok(Some(RedactionEntry {
        path: path.display().to_string(),
        secrets_redacted: count,
        backup_path: Some(backup_path.display().to_string()),
        applied: true,
    }))
}

/// Streams `file` a line at a time: each line goes verbatim to the 0600 backup at `backup_path`,
/// and its redacted form to `tmp`. Returns how many secrets were replaced. Bounded memory (one
/// line) regardless of file size. Both destinations are created `O_EXCL | O_NOFOLLOW` so a raced
/// symlink or pre-existing name can't be written through.
fn stream_to_backup_and_temp(
    file: std::fs::File,
    backup_path: &Path,
    tmp: &Path,
) -> anyhow::Result<usize> {
    use std::io::{BufRead, BufReader, BufWriter, Write};
    let mut reader = BufReader::new(file);
    let mut backup = BufWriter::new(create_owner_only(backup_path)?);
    let mut out = BufWriter::new(create_temp_exclusive(tmp)?);

    let mut count = 0usize;
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        backup.write_all(&line)?;
        match std::str::from_utf8(&line) {
            Ok(s) => {
                let (redacted, n) = secrets::redact_text(s);
                count += n;
                out.write_all(redacted.as_bytes())?;
            }
            // A non-UTF-8 line can't be redacted as text; write it through unchanged so a mixed or
            // binary file is preserved byte-for-byte rather than corrupted.
            Err(_) => out.write_all(&line)?,
        }
    }
    backup.flush()?;
    out.flush()?;
    Ok(count)
}

/// Counts (without writing) the redactable secrets in `reader`, streaming a line at a time.
fn count_redactions<R: std::io::BufRead>(mut reader: R) -> anyhow::Result<usize> {
    let mut count = 0usize;
    let mut line: Vec<u8> = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&line) {
            count += secrets::redact_text(s).1;
        }
    }
    Ok(count)
}

/// The backup path for `path` under `backup_dir`: its components joined by `_`, suffixed `.bak`,
/// with a numeric suffix on collision so an earlier backup is never overwritten.
fn backup_target(path: &Path, backup_dir: &Path) -> PathBuf {
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
    candidate
}

/// Creates a fresh file that is owner-only (0600) from the instant it exists (`O_EXCL`, no
/// pre-existing name / symlink; `O_NOFOLLOW`). Returned open for streaming — the backup of a
/// secret file must never have even a brief world-readable window.
#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
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

    #[test]
    fn streams_a_large_multiline_file_redacting_only_the_secret_lines() {
        // Mimics a session transcript: a secret buried deep among many lines, in a file far larger
        // than the old 8 MB whole-file cap that made redaction refuse these outright. Streaming must
        // find and redact it, preserve every other line, and back the original up.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("session.jsonl");
        let key = anthropic_key();
        let mut content = String::new();
        for i in 0..200_000 {
            content.push_str(&format!(
                "{{\"line\":{i},\"text\":\"ordinary log content here\"}}\n"
            ));
        }
        content.push_str(&format!("{{\"secret\":\"{key}\"}}\n"));
        for i in 0..200_000 {
            content.push_str(&format!("{{\"line\":{i},\"more\":\"tail content\"}}\n"));
        }
        assert!(
            content.len() > 12 * 1024 * 1024,
            "fixture exceeds the old cap"
        );
        std::fs::write(&file, &content).unwrap();

        let report = redact_paths(std::slice::from_ref(&file), true, &dir.path().join("b"));
        assert_eq!(
            report.total_secrets, 1,
            "the buried secret is found and redacted"
        );
        let after = std::fs::read_to_string(&file).unwrap();
        assert!(!after.contains(&key), "secret is gone");
        assert!(after.contains(secrets::REDACTION_PLACEHOLDER));
        assert!(
            after.contains("ordinary log content here"),
            "other lines preserved"
        );
        assert!(
            after.contains("tail content"),
            "content after the secret preserved"
        );
        // The backup holds the original secret.
        let backup = report.entries[0].backup_path.as_ref().unwrap();
        assert!(std::fs::read_to_string(backup).unwrap().contains(&key));
    }
}
