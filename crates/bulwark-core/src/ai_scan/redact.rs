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
use rayon::prelude::*;
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
    // Each path is redacted independently — its own read, backup, temp, and atomic rename touch
    // only that one file — so the set runs in parallel, on the same bounded pool as the scan so it
    // never pins every core. `collect` preserves input order, so the reported entries stay in the
    // caller's (severity-sorted) order regardless of thread timing.
    let run = || -> Vec<Result<Option<RedactionEntry>, String>> {
        paths
            .par_iter()
            .map(|path| {
                redact_one(path, apply, backup_dir).map_err(|e| format!("{}: {e}", path.display()))
            })
            .collect()
    };
    let outcomes = match super::bounded_scan_pool() {
        Some(pool) => pool.install(run),
        None => run(),
    };

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut total = 0usize;
    for outcome in outcomes {
        match outcome {
            Ok(Some(entry)) => {
                total += entry.secrets_redacted;
                entries.push(entry);
            }
            Ok(None) => {}
            Err(e) => errors.push(e),
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

    // Apply. The scanner reads (and therefore only ever flags) the first `MAX_SCAN_BYTES` of a file,
    // so redaction buffers that same prefix, redacts it as ONE unit, and streams any tail beyond it
    // through verbatim. Redacting as one unit is essential: multi-line secrets (a PEM private key, a
    // Kubernetes YAML secret) span many lines and can never match a line-at-a-time pass — the
    // previous line-oriented redactor reported those files "redactable" and then left the secret on
    // disk. The original bytes go to a 0600 backup; the temp is swapped in atomically.
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

/// Buffers the first `MAX_SCAN_BYTES` of `file` (the same window the scanner reads), writes those
/// bytes verbatim to the 0600 backup, redacts them as one unit to `tmp`, then streams any tail past
/// the window through to both verbatim. Returns how many secrets were replaced. Redacting the prefix
/// as a whole — not line-by-line — is what lets a multi-line secret (PEM key, k8s YAML) actually be
/// removed. Both destinations are created `O_EXCL | O_NOFOLLOW` so a raced symlink or pre-existing
/// name can't be written through. Memory is bounded by the scan-window cap plus a fixed tail buffer.
fn stream_to_backup_and_temp(
    file: std::fs::File,
    backup_path: &Path,
    tmp: &Path,
) -> anyhow::Result<usize> {
    use std::io::{BufWriter, Read, Write};
    let mut reader = file;
    let mut backup = BufWriter::new(create_owner_only(backup_path)?);
    let mut out = BufWriter::new(create_temp_exclusive(tmp)?);

    // The flagged window: read at most the scanner's cap, redact it as one string. Rewriting a
    // non-UTF-8 file through a lossy decode would corrupt its bytes (turn each stray byte into a
    // 3-byte U+FFFD), so a file that isn't valid UTF-8 is REFUSED rather than mangled — the caller
    // reports it and the user handles it by hand. The scanner reads such files lossily to *find*
    // secrets, but writing is held to the stricter bar.
    let cap = super::MAX_SCAN_BYTES as u64;
    let mut head = Vec::new();
    (&mut reader).take(cap).read_to_end(&mut head)?;
    let head_str = std::str::from_utf8(&head).map_err(|_| {
        anyhow::anyhow!("file is not valid UTF-8; refusing to rewrite it (redact this one by hand)")
    })?;
    backup.write_all(&head)?;
    let (redacted, count) = secrets::redact_text(head_str);
    out.write_all(redacted.as_bytes())?;

    // Anything past the scan window was never inspected, so it carries no flagged secret — copy it
    // through verbatim in bounded chunks (so a tens-of-MB transcript stays memory-safe).
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        backup.write_all(&buf[..n])?;
        out.write_all(&buf[..n])?;
    }
    backup.flush()?;
    out.flush()?;
    Ok(count)
}

/// Counts (without writing) the redactable secrets in the scan window of `reader` — buffered and
/// counted as one unit, so the dry-run number matches what an actual apply will remove (including
/// multi-line secrets a line-at-a-time count would miss).
fn count_redactions<R: std::io::Read>(mut reader: R) -> anyhow::Result<usize> {
    use std::io::Read;
    let mut head = Vec::new();
    (&mut reader)
        .take(super::MAX_SCAN_BYTES as u64)
        .read_to_end(&mut head)?;
    Ok(secrets::redact_text(&String::from_utf8_lossy(&head)).1)
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
    // Create the temp `0600`, then widen to the original file's mode only at the final
    // `set_permissions` before the rename. Otherwise the temp — which holds the file's content,
    // possibly still carrying report-only (non-redacted) secret material — would briefly sit at the
    // umask default (typically `0644`), world-readable, in a shared directory.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
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
        // Mimics a session transcript: a single-line secret buried among many lines within the scan
        // window, plus a large tail past the window. Redaction must find and redact the secret,
        // preserve every other line, stream the tail through, and back the original up.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("session.jsonl");
        let key = anthropic_key();
        let mut content = String::new();
        // ~1 MB of preamble, then the secret — comfortably inside MAX_SCAN_BYTES (4 MB).
        for i in 0..20_000 {
            content.push_str(&format!(
                "{{\"line\":{i},\"text\":\"ordinary log content here\"}}\n"
            ));
        }
        content.push_str(&format!("{{\"secret\":\"{key}\"}}\n"));
        // A large tail past the 4 MB window — must be preserved verbatim by the streaming copy.
        for i in 0..200_000 {
            content.push_str(&format!("{{\"line\":{i},\"more\":\"tail content\"}}\n"));
        }
        assert!(
            content.len() > 6 * 1024 * 1024,
            "fixture's tail extends well past the 4 MB scan window"
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

    #[test]
    fn a_multiline_private_key_is_actually_redacted_not_just_reported() {
        // The critical bug: a PEM private key spans ~25 lines, so a line-at-a-time redactor never
        // matched it — the file was reported "redactable" and the key left on disk. Redacting the
        // window as one unit must actually remove it.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("CLAUDE.md");
        let body: String = std::iter::repeat_n("QUFBQUFBQUFBQUFBQUFBQQ", 40)
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
        );
        std::fs::write(
            &file,
            format!("# notes\nhere is a key:\n{pem}\ntrailing text\n"),
        )
        .unwrap();

        // Dry-run must count it (so the UI's "redactable" claim is honest)...
        let dry = redact_paths(std::slice::from_ref(&file), false, &dir.path().join("b"));
        assert!(
            dry.total_secrets >= 1,
            "dry-run must see the multi-line key"
        );

        // ...and apply must actually remove it from disk.
        let report = redact_paths(std::slice::from_ref(&file), true, &dir.path().join("b"));
        assert!(report.total_secrets >= 1);
        let after = std::fs::read_to_string(&file).unwrap();
        assert!(
            !after.contains("BEGIN OPENSSH PRIVATE KEY"),
            "the multi-line key must be gone from the file, not merely reported: {after}"
        );
        assert!(
            after.contains("trailing text"),
            "surrounding content preserved"
        );
    }
}
