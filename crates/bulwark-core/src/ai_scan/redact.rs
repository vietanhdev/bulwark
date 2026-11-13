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
//!
//! Rewriting a user's file is the one thing here that cannot be taken back, so every way it could
//! go wrong is refused out loud rather than worked around:
//!
//! * **Only a file that really is inside an agent's own folder** ([`rewrite_refusal`]). From that
//!   folder down to the file nothing may be a link, so a repository that tracks
//!   `.claude/commands -> ../../../Documents` cannot aim the rewrite at the user's own documents.
//!   This is checked here, independently of the scan that produced the list of files.
//! * **Never a file that is being written to.** A file changed in the last [`ACTIVE_SECONDS`] is
//!   left alone unless the caller says otherwise, and a file that changes while it is being
//!   rewritten is read again, a few times, and then refused — replacing it would silently drop the
//!   lines an agent appended in between.
//! * **All of the file, and all of its keys.** The file is rewritten a window at a time
//!   ([`redact_stream`]), each window until nothing more is found in it, and the result is read
//!   back with the scanner's own eyes: anything still there is reported, never passed over.
//! * **The backup holds the original, key included.** It is `0600` in a `0700` folder, and it
//!   stays until the user deletes it; callers must say so.

use super::{chunks, secrets};
use crate::homefs;
use rayon::prelude::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// One file the redaction pass considered. `secrets_redacted` is how many high-confidence
/// secrets were found (and, if `applied`, replaced). `backup_path` is set only when a backup was
/// actually written (`apply = true` and at least one secret present).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RedactionEntry {
    pub path: String,
    pub secrets_redacted: usize,
    /// Secrets the scanner still finds in the file after it was rewritten. Zero unless something
    /// went wrong; when it is not zero the file is named in the report's `errors` as well.
    pub secrets_remaining: usize,
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

impl RedactionReport {
    /// True when some file that was meant to be redacted still holds a key: it was refused, it
    /// failed, or keys were left in it. A caller that applied the redaction must not report
    /// success when this is true.
    pub fn unfinished(&self) -> bool {
        !self.errors.is_empty() || self.entries.iter().any(|e| e.secrets_remaining > 0)
    }
}

/// How a redaction pass behaves.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactOptions {
    /// Rewrite the files. Without it, only count what would be replaced.
    pub apply: bool,
    /// Also rewrite a file that was changed in the last [`ACTIVE_SECONDS`]. Off by default: such a
    /// file is probably the transcript of a session that is still running.
    pub include_active: bool,
}

/// A file changed more recently than this is treated as in use.
pub const ACTIVE_SECONDS: u64 = 30;

/// Words that appear in the error for a file left alone because it is in use, so a caller can
/// recognise that case and say what to do about it.
pub const IN_USE: &str = "may still be writing to it";

/// How often a file that changed while it was being rewritten is read again before giving up.
const MAX_ATTEMPTS: usize = 3;

/// How many times one window is redacted again to pick up what a capped pass left behind.
const MAX_PASSES: usize = 256;

/// Redacts (or, in dry-run, previews redacting) every high-confidence secret in `paths`.
/// `backup_dir` receives a `0600` copy of each modified file before it's overwritten, with the
/// file's original path recorded beside it; it's created if absent. In dry-run mode files are read
/// but never written and no backups are made. A file changed in the last few seconds is refused
/// (see [`redact_with`] to override that).
pub fn redact_paths(paths: &[PathBuf], apply: bool, backup_dir: &Path) -> RedactionReport {
    redact_with(
        paths,
        RedactOptions {
            apply,
            include_active: false,
        },
        backup_dir,
    )
}

/// [`redact_paths`] with every option.
pub fn redact_with(paths: &[PathBuf], opts: RedactOptions, backup_dir: &Path) -> RedactionReport {
    // Each path is redacted independently — its own read, backup, temp, and atomic rename touch
    // only that one file — so the set runs in parallel, on the same bounded pool as the scan so it
    // never pins every core. `collect` preserves input order, so the reported entries stay in the
    // caller's (severity-sorted) order regardless of thread timing.
    let run = || -> Vec<Result<Option<Done>, String>> {
        paths
            .par_iter()
            .map(|path| {
                redact_one(path, opts, backup_dir).map_err(|e| format!("{}: {e}", path.display()))
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
            Ok(Some(done)) => {
                total += done.entry.secrets_redacted;
                errors.extend(
                    done.notes
                        .into_iter()
                        .map(|n| format!("{}: {n}", done.entry.path)),
                );
                entries.push(done.entry);
            }
            Ok(None) => {}
            Err(e) => errors.push(e),
        }
    }

    RedactionReport {
        dry_run: !opts.apply,
        entries,
        total_secrets: total,
        errors,
    }
}

/// One file's result, with anything about it the user has to be told.
struct Done {
    entry: RedactionEntry,
    notes: Vec<String>,
}

/// Whether `path` is a dotenv-family file (`.env`, `.env.local`, `.env.production`, …) — a file
/// whose entire purpose is to hold working secrets, and which must therefore never be rewritten.
fn is_dotenv_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == ".env" || n.starts_with(".env."))
        .unwrap_or(false)
}

/// Why redaction will not rewrite `path`, if it will not. `None` means it would.
///
/// This is the whole of the "where may a rewrite land" rule, and the scan asks it too, so a
/// finding is marked redactable only when redaction would really do it:
///
/// * never a dotenv file — its secrets are read back by something, and rewriting them breaks the
///   project and destroys the only copy of the key in that file;
/// * only inside an agent's own folder (`.claude`, `.cursor`, `~/.config/opencode`, …) — a
///   `CLAUDE.md` at a project root sits among the files the developer edits and commits;
/// * from that folder down to the file, every name must be the real thing. A link anywhere on the
///   way — the folder itself, a folder inside it, the file — could send the rewrite to a file
///   outside the folder, so it is refused, whether or not the link happens to stay inside;
/// * a regular file with one name. A second hard link would keep the key under its other name.
pub(super) fn rewrite_refusal(path: &Path) -> Option<String> {
    if is_dotenv_path(path) {
        return Some(
            "refusing to rewrite a dotenv file — its secrets are functional and rewriting them \
             would break the project; rotate the key instead"
                .to_string(),
        );
    }
    let Some(anchor) = super::agent_dir_index(path) else {
        return Some(
            "it is not inside an agent's own folder, and redaction only rewrites files there"
                .to_string(),
        );
    };
    let parts: Vec<std::path::Component<'_>> = path.components().collect();
    let mut cur: PathBuf = parts[..anchor].iter().collect();
    for (i, part) in parts.iter().enumerate().skip(anchor) {
        // `..` after the agent folder would walk straight back out of it.
        if !matches!(part, std::path::Component::Normal(_)) {
            return Some("its path leaves the agent's folder again (`..`)".to_string());
        }
        cur.push(part);
        let meta = match std::fs::symlink_metadata(&cur) {
            Ok(meta) => meta,
            Err(e) => return Some(format!("{} could not be examined ({e})", cur.display())),
        };
        if meta.file_type().is_symlink() {
            return Some(format!(
                "it is reached through a link ({}), and redaction never rewrites through a link",
                cur.display()
            ));
        }
        let is_file_itself = i + 1 == parts.len();
        if is_file_itself {
            if !meta.is_file() {
                return Some("it is not a regular file".to_string());
            }
            if hard_links(&meta) > 1 {
                return Some(
                    "it has a second name (a hard link), which would keep the secret".to_string(),
                );
            }
        } else if !meta.is_dir() {
            return Some(format!("{} is not a folder", cur.display()));
        }
    }
    None
}

fn redact_one(path: &Path, opts: RedactOptions, backup_dir: &Path) -> anyhow::Result<Option<Done>> {
    // Decided here, from the path as it is on disk now, whatever the caller checked earlier:
    // redaction rewrites real user files, and a single wrong one is irreversible.
    if let Some(why) = rewrite_refusal(path) {
        anyhow::bail!("not rewritten: {why}");
    }
    // Opened through the agent folder as a boundary: if a name on the way is swapped for a link
    // after the check above, the open refuses instead of following it, and it never waits on a
    // pipe. `rewrite_refusal` returned `None`, so the agent folder is known.
    let anchor = super::agent_dir_index(path).unwrap_or(0);
    let agent_dir: PathBuf = path.components().take(anchor + 1).collect();
    let root = homefs::Root::new(&agent_dir)
        .ok_or_else(|| anyhow::anyhow!("not rewritten: its folder could not be resolved"))?;
    let mut file = match root.try_open(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(why) => anyhow::bail!("not rewritten: {why}"),
    };
    let path_text = path.display().to_string();

    // Dry-run: read the file the way a rewrite would, writing nothing.
    if !opts.apply {
        let outcome = redact_stream(&mut file, &path_text, &mut |_, _| Ok(()))?;
        return Ok((outcome.count > 0).then(|| Done {
            entry: RedactionEntry {
                path: path_text,
                secrets_redacted: outcome.count,
                secrets_remaining: 0,
                backup_path: None,
                applied: false,
            },
            notes: Vec::new(),
        }));
    }

    if !opts.include_active {
        // A modification time in the future says nothing reassuring either.
        let age = file
            .metadata()?
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok());
        if age.is_none_or(|age| age.as_secs() < ACTIVE_SECONDS) {
            anyhow::bail!(
                "not rewritten: it was changed in the last {ACTIVE_SECONDS} seconds, so an agent \
                 {IN_USE}. Try again when that session has ended"
            );
        }
    }

    std::fs::create_dir_all(backup_dir)?;
    // The backup holds the ORIGINAL, un-redacted secret — lock its directory to owner-only.
    set_dir_owner_only(backup_dir);

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    // A name nobody can guess, created exclusively: nothing planted beforehand can be written
    // through, and a long file name cannot make the temporary name too long.
    let tmp = dir.join(format!(
        ".bulwark-redact-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));

    // Read, write the backup and the redacted copy, then make sure the file is still what was
    // read. If something appended to it meanwhile (or put another file under its name), start
    // again from what is there now.
    let mut attempt = 0;
    let (original, backup_path, outcome) = loop {
        attempt += 1;
        if attempt > 1 {
            file = match root.try_open(path) {
                Ok(Some(file)) => file,
                Ok(None) => return Ok(None),
                Err(why) => anyhow::bail!("not rewritten: {why}"),
            };
        }
        let before = file.metadata()?;
        file.seek(SeekFrom::Start(0))?;
        let (backup_file, backup_path) = create_backup(path, backup_dir)?;
        let result = write_backup_and_temp(&mut file, &path_text, backup_file, &tmp);
        checkpoint("written", path);
        let discard = || {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(&backup_path);
        };
        match result {
            Err(e) => {
                discard();
                return Err(e);
            }
            Ok(outcome) if unchanged_since(&file, &before, path, outcome.bytes) => {
                break (before, backup_path, outcome)
            }
            Ok(_) => {
                discard();
                if attempt >= MAX_ATTEMPTS {
                    anyhow::bail!(
                        "not rewritten: the file is in use — it kept changing while it was being \
                         read, so an agent {IN_USE}. Try again when that session has ended"
                    );
                }
            }
        }
    };
    let discard = || {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&backup_path);
    };

    if outcome.count == 0 {
        // Flagged, but nothing high-confidence to rewrite — leave the original untouched.
        discard();
        return Ok(None);
    }

    // Read the result back the way the scanner reads a file. Redaction and detection share one
    // matcher, so this should find nothing; if it ever does, the user is told which file still
    // holds a key instead of being told it was removed.
    let remaining = match count_keys(&tmp, &path_text) {
        Ok(n) => n,
        Err(e) => {
            discard();
            return Err(e.into());
        }
    };
    let mut notes = Vec::new();
    if remaining > 0 || !outcome.converged {
        notes.push(format!(
            "{} still in the file after redaction — remove {} by hand",
            if remaining == 1 {
                "1 secret is".to_string()
            } else {
                format!("{} secrets are", remaining.max(1))
            },
            if remaining == 1 { "it" } else { "them" },
        ));
    }

    // Preserve the original's permission bits on the redacted copy, record where the backup came
    // from, then swap the copy in atomically.
    let prepared = std::fs::set_permissions(&tmp, original.permissions())
        .and_then(|()| record_origin(&backup_path, path));
    if let Err(e) = prepared {
        discard();
        let _ = std::fs::remove_file(origin_record(&backup_path));
        return Err(e.into());
    }
    checkpoint("checked", path);
    if let Err(e) = std::fs::rename(&tmp, path) {
        discard();
        let _ = std::fs::remove_file(origin_record(&backup_path));
        return Err(e.into());
    }
    // Anything written to the old file in the instant between the last look and the swap is still
    // reachable through the open descriptor: bring it across rather than lose it.
    if let Err(e) = carry_over_late_writes(&mut file, outcome.bytes, path) {
        notes.push(format!(
            "lines written to the file while it was being replaced could not be carried over \
             ({e}); they are not in the backup either"
        ));
    }

    Ok(Some(Done {
        entry: RedactionEntry {
            path: path_text,
            secrets_redacted: outcome.count,
            secrets_remaining: remaining,
            backup_path: Some(backup_path.display().to_string()),
            applied: true,
        },
        notes,
    }))
}

/// How many names the file has. More than one means a hard link.
#[cfg(unix)]
fn hard_links(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(not(unix))]
fn hard_links(_meta: &std::fs::Metadata) -> u64 {
    1
}

/// Whether two descriptions are of one and the same file.
#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.len() == b.len() && a.modified().ok() == b.modified().ok()
}

/// A hook for tests to change a file at an exact point in a rewrite. Does nothing otherwise.
fn checkpoint(stage: &'static str, path: &Path) {
    #[cfg(test)]
    tests::HOOK.with(|hook| {
        if let Some(f) = hook.borrow_mut().as_mut() {
            f(stage, path);
        }
    });
    let _ = (stage, path);
}

/// Whether the file is still exactly what was read: the same file under that name, the same
/// length as the bytes consumed, not modified since the read began.
fn unchanged_since(
    file: &std::fs::File,
    before: &std::fs::Metadata,
    path: &Path,
    bytes_read: u64,
) -> bool {
    let Ok(now) = file.metadata() else {
        return false;
    };
    if now.len() != bytes_read || now.modified().ok() != before.modified().ok() {
        return false;
    }
    // The name must still lead to this very file, not to one swapped in beside it.
    std::fs::symlink_metadata(path).is_ok_and(|named| named.is_file() && same_file(&named, &now))
}

/// After the swap: copies anything that reached the old file past what was read onto the end of
/// the new one. Returns how many bytes were carried.
fn carry_over_late_writes(
    old: &mut std::fs::File,
    mut consumed: u64,
    path: &Path,
) -> std::io::Result<u64> {
    let mut carried = 0u64;
    for _ in 0..MAX_ATTEMPTS {
        let len = old.metadata()?.len();
        if len <= consumed {
            break;
        }
        old.seek(SeekFrom::Start(consumed))?;
        let mut late = Vec::new();
        old.take(len - consumed).read_to_end(&mut late)?;
        if late.is_empty() {
            break;
        }
        let mut new = open_append_no_follow(path)?;
        new.write_all(&late)?;
        new.sync_all()?;
        consumed += late.len() as u64;
        carried += late.len() as u64;
    }
    Ok(carried)
}

/// What one pass over a file did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StreamOutcome {
    /// Secrets replaced.
    count: usize,
    /// Bytes read from the file.
    bytes: u64,
    /// False when a window still held secrets after [`MAX_PASSES`] passes over it.
    converged: bool,
}

/// Writes the original bytes of `file` to the 0600 backup and the redacted text to `tmp`, a window
/// at a time. The temp is created `O_EXCL | O_NOFOLLOW`, so a raced link or a pre-existing name
/// can't be written through. Memory is one window, whatever the file's size.
fn write_backup_and_temp(
    file: &mut std::fs::File,
    path: &str,
    backup: std::fs::File,
    tmp: &Path,
) -> anyhow::Result<StreamOutcome> {
    let mut backup = std::io::BufWriter::new(backup);
    let mut out = std::io::BufWriter::new(create_temp_exclusive(tmp)?);
    let outcome = redact_stream(file, path, &mut |original, redacted| {
        backup.write_all(original)?;
        out.write_all(redacted.as_bytes())
    })?;
    // On disk before anything is swapped: a crash must never leave a half-written file in place
    // of the original.
    backup
        .into_inner()
        .map_err(|e| e.into_error())?
        .sync_all()?;
    out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    Ok(outcome)
}

/// Reads all of `reader` and hands `emit` each piece twice over: the original bytes, and the same
/// text with every high-confidence secret replaced.
///
/// The file is taken a window at a time, and each window is redacted as ONE unit — a multi-line
/// secret (a PEM private key, a Kubernetes YAML secret) can never match a line-at-a-time pass.
/// The pieces do not overlap, so every byte is written exactly once; what keeps a secret from
/// being cut in two is where the pieces end. Each ends about [`chunks::OVERLAP_BYTES`] before the
/// end of what is in memory, at the start of a line, and only after [`safe_split`] has confirmed
/// that nothing — a key, or the words a rule needs beside it — lies across that point. The text
/// after it is carried into the next window.
///
/// A file that is not valid UTF-8 is REFUSED, not rewritten through a lossy decode that would
/// turn each stray byte into a 3-byte U+FFFD. A character cut by the end of a window is not a
/// stray byte: the split points never fall inside one.
fn redact_stream(
    reader: &mut dyn Read,
    path: &str,
    emit: &mut dyn FnMut(&[u8], &str) -> std::io::Result<()>,
) -> anyhow::Result<StreamOutcome> {
    redact_stream_sized(
        reader,
        path,
        chunks::WINDOW_BYTES,
        chunks::OVERLAP_BYTES,
        emit,
    )
}

fn not_utf8() -> anyhow::Error {
    anyhow::anyhow!("file is not valid UTF-8; refusing to rewrite it (redact this one by hand)")
}

fn redact_stream_sized(
    reader: &mut dyn Read,
    path: &str,
    window: usize,
    overlap: usize,
    emit: &mut dyn FnMut(&[u8], &str) -> std::io::Result<()>,
) -> anyhow::Result<StreamOutcome> {
    let mut outcome = StreamOutcome {
        count: 0,
        bytes: 0,
        converged: true,
    };
    let mut buf: Vec<u8> = Vec::new();
    let mut eof = false;
    loop {
        let want = window.saturating_sub(buf.len());
        if !eof && want > 0 {
            let got = chunks::fill(reader, &mut buf, want)?;
            outcome.bytes += got as u64;
            eof = got < want;
        }
        if buf.is_empty() {
            break;
        }
        let commit = if eof {
            buf.len()
        } else {
            safe_split(&buf, path, overlap)?
        };
        let text = std::str::from_utf8(&buf[..commit]).map_err(|_| not_utf8())?;
        let (redacted, count, converged) = redact_fully(path, text);
        outcome.count += count;
        outcome.converged &= converged;
        emit(&buf[..commit], &redacted)?;
        if eof {
            break;
        }
        buf.drain(..commit);
    }
    Ok(outcome)
}

/// Redacts `text` until a pass finds nothing more. One pass replaces a bounded number of secrets
/// (the matcher caps what it collects from one text), so a file holding thousands used to come
/// back "redacted" with most of them still in it.
fn redact_fully(path: &str, text: &str) -> (String, usize, bool) {
    let (mut current, mut total) = secrets::redact_text_in(Some(path), text);
    if total == 0 {
        return (current, 0, true);
    }
    for _ in 0..MAX_PASSES {
        let (next, count) = secrets::redact_text_in(Some(path), &current);
        if count == 0 {
            return (current, total, true);
        }
        total += count;
        current = next;
    }
    (current, total, false)
}

/// A place in a full window where it can be split without changing what redaction finds: the
/// start of a line about `overlap` bytes before the end.
///
/// "Without changing" is checked, not assumed. The text around the candidate is redacted once as
/// a whole and once as two halves; if the results differ, something lies across the candidate — a
/// multi-line key, or a key on one side and the name a rule needs on the other — and the split
/// moves back to before it.
fn safe_split(buf: &[u8], path: &str, overlap: usize) -> anyhow::Result<usize> {
    let mut at = split_before(buf, buf.len().saturating_sub(overlap));
    for _ in 0..8 {
        if at == 0 {
            break;
        }
        // The stretch that is looked at: from about `overlap` before the candidate to the end of
        // what is in memory (trimmed of a character the end of the window cut in two).
        let mut from = chunks::next_start(buf, at, overlap);
        if from >= at {
            from = split_before(buf, at.saturating_sub(overlap)).min(at);
        }
        let seam = match std::str::from_utf8(&buf[from..]) {
            Ok(seam) => seam,
            Err(e) if e.error_len().is_none() && from + e.valid_up_to() >= at => {
                std::str::from_utf8(&buf[from..from + e.valid_up_to()]).map_err(|_| not_utf8())?
            }
            Err(_) => return Err(not_utf8()),
        };
        let (left, right) = seam.split_at(at - from);
        let whole = secrets::redact_text_in(Some(path), seam).0;
        let left = secrets::redact_text_in(Some(path), left).0;
        let right = secrets::redact_text_in(Some(path), right).0;
        if whole.len() == left.len() + right.len()
            && whole.starts_with(&left)
            && whole.ends_with(&right)
        {
            return Ok(at);
        }
        if from == at {
            break;
        }
        at = from;
    }
    anyhow::bail!(
        "no safe place to split this file was found (a secret in it seems to span more than {} KB); \
         redact this one by hand",
        overlap / 1024
    )
}

/// The start of the last line that begins at or before `target` (not looking further back than
/// the middle of the buffer), else just after a space or quote, else a whole character.
fn split_before(buf: &[u8], target: usize) -> usize {
    let target = target.min(buf.len());
    let floor = (buf.len() / 2).min(target);
    let back = &buf[floor..target];
    if let Some(i) = back.iter().rposition(|b| *b == b'\n') {
        return floor + i + 1;
    }
    if let Some(i) = back
        .iter()
        .rposition(|b| matches!(*b, b' ' | b'\t' | b'\r' | b'"'))
    {
        return floor + i + 1;
    }
    chunks::floor_char_boundary(buf, target)
}

/// How many high-confidence secrets the scanner finds in the file at `file_path`, read exactly as
/// a scan reads it. `scanned_as` is the path the rules are applied for.
fn count_keys(file_path: &Path, scanned_as: &str) -> std::io::Result<usize> {
    let file = open_no_follow(file_path)?;
    let size = file.metadata()?.len();
    let mut seen = std::collections::HashSet::new();
    chunks::for_each_window(file, size, u64::MAX, |window| {
        for key in secrets::scan_text_high_confidence_in(Some(scanned_as), &window.text) {
            seen.insert((key.line + window.first_line - 1, key.rule_id, key.redacted));
        }
    })?;
    Ok(seen.len())
}

/// A short name for the backup of `path`: a hash of the whole path, then the file's own name with
/// anything unusual replaced. The whole path used to be flattened into the name, which made a
/// deeply nested transcript's backup name longer than a file name may be (255 bytes), so the
/// redaction failed; and on Windows a name starting `C:` is a drive prefix, which sent the backup
/// of a secret outside the owner-only backup folder.
fn backup_stem(path: &Path) -> String {
    // FNV-1a: only to tell two files with the same name apart. Collisions are handled by the
    // numbered names in `create_backup`, and the real path is recorded beside the backup.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let text = path.to_string_lossy();
    let name = text.rsplit(['/', '\\']).next().unwrap_or("file");
    let name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    format!("{hash:016x}-{name}")
}

/// Creates the backup file for `path`: owner-only from the instant it exists, under a name that
/// was not there before, so an earlier backup is never overwritten.
fn create_backup(path: &Path, backup_dir: &Path) -> std::io::Result<(std::fs::File, PathBuf)> {
    let stem = backup_stem(path);
    for n in 0..10_000u32 {
        let name = if n == 0 {
            format!("{stem}.bak")
        } else {
            format!("{stem}.{n}.bak")
        };
        let candidate = backup_dir.join(name);
        match create_owner_only(&candidate) {
            Ok(file) => return Ok((file, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(
        "too many backups of this file already exist",
    ))
}

/// Where the original path of a backup is written down: `<backup>.path`.
fn origin_record(backup: &Path) -> PathBuf {
    let mut name = backup.as_os_str().to_os_string();
    name.push(".path");
    PathBuf::from(name)
}

/// Records which file a backup is a copy of, since its name no longer says.
fn record_origin(backup: &Path, original: &Path) -> std::io::Result<()> {
    let mut file = create_owner_only(&origin_record(backup))?;
    file.write_all(original.as_os_str().as_encoded_bytes())?;
    file.write_all(b"\n")
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

/// Opens an existing file to add to its end, never through a link.
#[cfg(unix)]
fn open_append_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_append_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().append(true).open(path)
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
    use std::cell::RefCell;
    use std::time::{Duration, SystemTime};

    thread_local! {
        /// Called at named points of a rewrite on this thread (see `checkpoint`).
        #[allow(clippy::type_complexity)]
        pub(super) static HOOK: RefCell<Option<Box<dyn FnMut(&'static str, &Path)>>> =
            const { RefCell::new(None) };
    }

    /// Runs `body` with `hook` installed for rewrites done on this thread.
    fn with_hook<T>(
        hook: impl FnMut(&'static str, &Path) + 'static,
        body: impl FnOnce() -> T,
    ) -> T {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        let out = body();
        HOOK.with(|h| *h.borrow_mut() = None);
        out
    }

    /// Shaped like an Anthropic key (prefix, length, suffix) and obviously not one.
    fn anthropic_key() -> String {
        format!("sk-ant-api03-{}AA", "a".repeat(93))
    }

    /// A different GitHub-token-shaped string for every `n`, made up on the spot.
    fn github_token(n: u64) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut state = n.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03;
        let body: String = (0..36)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ALPHABET[(state >> 33) as usize % ALPHABET.len()] as char
            })
            .collect();
        format!("ghp_{body}")
    }

    /// A path inside an agent's own folder under `dir`, which is where redaction may rewrite.
    fn agent_file(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(".claude/projects/p").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    /// Writes `content` and makes the file look an hour old, so it is not taken for one a session
    /// is still writing.
    fn write_old(path: &Path, content: impl AsRef<[u8]>) {
        std::fs::write(path, content).unwrap();
        make_old(path);
    }

    fn make_old(path: &Path) {
        let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
    }

    fn apply(path: &Path, backups: &Path) -> RedactionReport {
        redact_paths(std::slice::from_ref(&path.to_path_buf()), true, backups)
    }

    #[test]
    fn backup_names_are_short_plain_and_tell_files_apart() {
        let long = format!(
            "/home/someone/.claude/projects/{}/{}/subagents/agent-{}.jsonl",
            "-home-someone-Workspaces-customer-platform-services-payments-gateway-worktrees"
                .repeat(2),
            "11111111-2222-3333-4444-555555555555",
            "a".repeat(120),
        );
        for original in [
            r"C:\Users\me\.claude\projects\p\memory\notes.md",
            r"\\server\share\notes.md",
            "/home/me/.claude/projects/p/memory/notes.md",
            "/home/me/.claude/projects/p/memory/esc\u{1b}[31m\nname.md",
            long.as_str(),
        ] {
            let stem = backup_stem(Path::new(original));
            assert!(stem.len() <= 100, "{original} -> {stem}");
            assert!(
                stem.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
                "a backup name must be one plain file name: {stem}"
            );
        }
        // Two files with the same name in different folders get different backups.
        assert_ne!(
            backup_stem(Path::new("/a/.claude/notes.md")),
            backup_stem(Path::new("/b/.claude/notes.md"))
        );
        assert!(backup_stem(Path::new("/a/.claude/notes.md")).ends_with("-notes.md"));
    }

    #[test]
    fn dry_run_reports_without_changing_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "notes.md");
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
        let file = agent_file(dir.path(), "notes.md");
        let key = anthropic_key();
        write_old(&file, format!("token: {key}\nkeep this line\n"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        let backups = dir.path().join("backups");
        let report = apply(&file, &backups);
        assert_eq!(report.total_secrets, 1, "{:?}", report.errors);
        assert!(report.entries[0].applied);
        assert_eq!(report.entries[0].secrets_remaining, 0);
        assert!(!report.unfinished());

        // Exact content, not `contains`: a `contains("keep this line")` assertion still passed while
        // redaction was eating the newline the secret's rule had matched as its terminator, welding
        // the next line onto the placeholder. Only the secret's own bytes may change.
        let after = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            after,
            format!(
                "token: {}\nkeep this line\n",
                secrets::REDACTION_PLACEHOLDER
            ),
            "everything but the secret survives byte-for-byte"
        );
        assert!(!after.contains(&key), "secret must be gone from the file");

        // The backup holds the original secret and is 0600, and the file it came from is written
        // down beside it (the backup's own name is too short to say).
        let backup = report.entries[0].backup_path.as_ref().unwrap();
        let backup_content = std::fs::read_to_string(backup).unwrap();
        assert!(backup_content.contains(&key));
        assert_eq!(
            std::fs::read_to_string(format!("{backup}.path")).unwrap(),
            format!("{}\n", file.display())
        );
        // Nothing else is left behind next to the file.
        let siblings: Vec<_> = std::fs::read_dir(file.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(siblings, ["notes.md"]);

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
        write_old(&target, &original);
        // A symlink named like a scanned artifact, pointing at that target.
        let link = agent_file(dir.path(), "notes.md");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let report = apply(&link, &dir.path().join("b"));
        // The symlink is reported as an error, nothing is redacted, and the target is untouched.
        assert!(report.entries.is_empty());
        assert!(report.errors.iter().any(|e| e.contains("link")));
        assert!(report.unfinished());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
    }

    /// A repository tracks `.claude/commands -> ../../../Documents`. The file it "contains" is the
    /// user's own document: it must come back byte-for-byte, whichever folder on the way is the
    /// link, and whether the link leaves the project or stays inside it.
    #[cfg(unix)]
    #[test]
    fn a_link_anywhere_between_the_agent_folder_and_the_file_is_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let original = format!("personal note, token {}\n", anthropic_key());
        let documents = dir.path().join("Documents");
        std::fs::create_dir_all(documents.join("deep")).unwrap();
        write_old(&documents.join("notes.md"), &original);
        write_old(&documents.join("deep/notes.md"), &original);

        let repo = dir.path().join("Projects/evil");
        // 1. The spec folder itself is the link (the reported case).
        std::fs::create_dir_all(repo.join(".claude")).unwrap();
        symlink("../../../Documents", repo.join(".claude/commands")).unwrap();
        // 2. A folder below it is the link.
        std::fs::create_dir_all(repo.join(".cursor/rules")).unwrap();
        symlink(documents.join("deep"), repo.join(".cursor/rules/shared")).unwrap();
        // 3. The agent folder is the link.
        symlink(&documents, repo.join(".gemini")).unwrap();
        // 4. A link that stays inside the project is refused just the same.
        std::fs::create_dir_all(repo.join("docs")).unwrap();
        write_old(&repo.join("docs/guide.md"), &original);
        std::fs::create_dir_all(repo.join(".roo")).unwrap();
        symlink("../docs", repo.join(".roo/rules")).unwrap();

        let backups = dir.path().join("b");
        for through in [
            ".claude/commands/notes.md",
            ".cursor/rules/shared/notes.md",
            ".gemini/notes.md",
            ".roo/rules/guide.md",
        ] {
            let path = repo.join(through);
            assert!(
                path.exists(),
                "{through} must resolve, or the test proves nothing"
            );
            assert!(rewrite_refusal(&path).is_some(), "{through}");
            let report = apply(&path, &backups);
            assert!(report.entries.is_empty(), "{through}: {report:?}");
            assert!(
                report.errors.iter().any(|e| e.contains("link")),
                "{through}: {:?}",
                report.errors
            );
        }
        for untouched in ["Documents/notes.md", "Documents/deep/notes.md"] {
            assert_eq!(
                std::fs::read_to_string(dir.path().join(untouched)).unwrap(),
                original,
                "{untouched} must be byte-for-byte unchanged"
            );
        }
        assert_eq!(
            std::fs::read_to_string(repo.join("docs/guide.md")).unwrap(),
            original
        );
        assert!(
            !backups.exists(),
            "a refused file must not be copied anywhere"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_file_with_a_second_name_or_outside_an_agent_folder_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let original = format!("token {}\n", anthropic_key());
        // A hard link: the user's own file under a second name inside an agent folder.
        let own = dir.path().join("my-notes.md");
        write_old(&own, &original);
        let linked = agent_file(dir.path(), "notes.md");
        std::fs::hard_link(&own, &linked).unwrap();
        let report = apply(&linked, &dir.path().join("b"));
        assert!(report.entries.is_empty());
        assert!(
            report.errors.iter().any(|e| e.contains("second name")),
            "{:?}",
            report.errors
        );
        assert_eq!(std::fs::read_to_string(&own).unwrap(), original);

        // A file at a project root is among the developer's own files: reported, never rewritten,
        // even when handed straight to redaction.
        let root_file = dir.path().join("CLAUDE.md");
        write_old(&root_file, &original);
        let report = apply(&root_file, &dir.path().join("b"));
        assert!(report.entries.is_empty());
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("agent's own folder")),
            "{:?}",
            report.errors
        );
        assert_eq!(std::fs::read_to_string(&root_file).unwrap(), original);

        // The same file named through an agent folder and back out of it.
        std::fs::create_dir_all(dir.path().join(".claude/commands")).unwrap();
        let roundabout = dir.path().join(".claude/commands/../../CLAUDE.md");
        assert!(roundabout.exists());
        assert!(rewrite_refusal(&roundabout).is_some());
        let report = apply(&roundabout, &dir.path().join("b"));
        assert!(report.entries.is_empty(), "{report:?}");
        assert_eq!(std::fs::read_to_string(&root_file).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_named_like_a_transcript_is_refused_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = agent_file(dir.path(), "a.jsonl");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let backups = dir.path().join("b");
        std::thread::spawn(move || {
            let _ = tx.send(redact_paths(std::slice::from_ref(&fifo), true, &backups));
        });
        let report = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("redaction must not wait on a pipe");
        assert!(report.entries.is_empty());
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
    }

    /// Backstop for the functional-config data-loss bug: even if a `.env` is passed to redaction
    /// directly (bypassing the scan's `kind_allows_redaction` gate), it must be refused and left
    /// **byte-for-byte unchanged** — no rewrite, no backup, an error the caller can see.
    #[test]
    fn a_dotenv_is_refused_and_left_untouched_even_if_passed_directly() {
        let dir = tempfile::tempdir().unwrap();
        for name in [".env", ".env.local", ".env.production"] {
            // Inside an agent folder too (`~/.gemini/.env` is one): the name alone decides.
            let file = dir.path().join(".gemini").join(name);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            let original = format!("ANTHROPIC_API_KEY={}\n", anthropic_key());
            write_old(&file, &original);

            let report = apply(&file, &dir.path().join("b"));

            assert!(
                report.entries.is_empty() && report.total_secrets == 0,
                "{name}: nothing may be redacted"
            );
            assert!(
                report.errors.iter().any(|e| e.contains("dotenv")),
                "{name}: the refusal must be surfaced as an error"
            );
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                original,
                "{name}: the file must be byte-for-byte unchanged"
            );
        }
    }

    #[test]
    fn dotenv_detection_is_precise() {
        assert!(is_dotenv_path(Path::new("/p/.env")));
        assert!(is_dotenv_path(Path::new("/p/.env.local")));
        assert!(is_dotenv_path(Path::new("/p/.env.production")));
        // Not dotenv files — these stay redactable if their kind allows.
        assert!(!is_dotenv_path(Path::new("/p/CLAUDE.md")));
        assert!(!is_dotenv_path(Path::new("/p/environment.md")));
        assert!(!is_dotenv_path(Path::new("/p/session.jsonl")));
    }

    #[test]
    fn a_clean_file_produces_no_entry() {
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "clean.md");
        write_old(&file, "no secrets here, just prose\n");
        let report = apply(&file, &dir.path().join("b"));
        assert!(report.entries.is_empty());
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.total_secrets, 0);
        // Nothing was kept for a file that was not changed.
        let left: Vec<_> = std::fs::read_dir(dir.path().join("b")).unwrap().collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn re_running_apply_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "x.md");
        write_old(&file, format!("{}\n", anthropic_key()));
        let backups = dir.path().join("b");
        let first = apply(&file, &backups);
        assert_eq!(first.total_secrets, 1, "{:?}", first.errors);
        make_old(&file);
        let second = apply(&file, &backups);
        assert_eq!(
            second.total_secrets, 0,
            "a redacted file has nothing left to redact"
        );
    }

    #[test]
    fn a_secret_anywhere_in_a_large_transcript_is_redacted_and_nothing_else_changes() {
        // A session transcript several windows long with a key near the start, one far past the
        // first 4 MB (which used to be copied through unread), and one on the very last line.
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "session.jsonl");
        let (early, late, last) = (github_token(1), github_token(2), github_token(3));
        let mut content = String::new();
        for i in 0..150_000 {
            if i == 20_000 {
                content.push_str(&format!("{{\"secret\":\"{early}\"}}\n"));
            }
            if i == 120_000 {
                content.push_str(&format!(
                    "{{\"type\":\"user\",\"message\":\"my token is {late} thanks\"}}\n"
                ));
            }
            content.push_str(&format!(
                "{{\"line\":{i},\"text\":\"ordinary log content here, nothing to see\"}}\n"
            ));
        }
        content.push_str(&format!("{{\"end\":\"{last}\"}}\n"));
        assert!(content.len() > 9 * 1024 * 1024, "{}", content.len());
        let late_offset = content.find(&late).unwrap();
        assert!(
            late_offset > 5 * 1024 * 1024,
            "the late key is past the old 4 MB window"
        );
        write_old(&file, &content);

        // The preview counts what the rewrite will remove.
        let dry = redact_paths(std::slice::from_ref(&file), false, &dir.path().join("b"));
        assert_eq!(dry.total_secrets, 3, "{:?}", dry.errors);

        let report = apply(&file, &dir.path().join("b"));
        assert_eq!(report.total_secrets, 3, "{:?}", report.errors);
        assert!(!report.unfinished());
        let after = std::fs::read_to_string(&file).unwrap();
        // Exactly the three keys changed: putting them back gives the original, byte for byte.
        let p = secrets::REDACTION_PLACEHOLDER;
        let mut restored = after.clone();
        for key in [&early, &late, &last] {
            assert!(!after.contains(key.as_str()), "a key is still in the file");
            restored = restored.replacen(p, key, 1);
        }
        assert!(restored == content, "only the keys' own bytes may change");
        // The backup is the original, whole.
        let backup = report.entries[0].backup_path.as_ref().unwrap();
        assert!(std::fs::read_to_string(backup).unwrap() == content);
    }

    #[test]
    fn a_multi_byte_character_across_a_window_edge_is_not_mistaken_for_bad_utf8() {
        // The reported case: a valid file a little over 4 MiB whose byte 4 MiB - 1 starts a
        // two-byte character. It was refused as "not valid UTF-8" and the key left in place.
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "u.jsonl");
        let key = github_token(7);
        let head = format!("{{\"m\":\"key {key}\"}}\n");
        let mut content = head.clone().into_bytes();
        content.resize(4 * 1024 * 1024 - 1, b'a');
        content.extend_from_slice("é end\n".as_bytes());
        assert!(std::str::from_utf8(&content).is_ok());
        write_old(&file, &content);

        let report = apply(&file, &dir.path().join("b"));
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.total_secrets, 1);
        let after = std::fs::read(&file).unwrap();
        let expected = String::from_utf8(content)
            .unwrap()
            .replace(&key, secrets::REDACTION_PLACEHOLDER);
        assert!(after == expected.as_bytes());

        // Every way a window edge can fall inside a character, with tiny windows.
        for pad in 0..8 {
            let text = format!("{}{}\nkey {key} é€😀\n", "x".repeat(pad), "é€😀".repeat(40));
            let mut out = String::new();
            let outcome = redact_stream_sized(
                &mut text.as_bytes(),
                "/h/.claude/t.md",
                64,
                16,
                &mut |_, r| {
                    out.push_str(r);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(outcome.count, 1, "pad {pad}");
            assert_eq!(
                out,
                text.replace(&key, secrets::REDACTION_PLACEHOLDER),
                "pad {pad}"
            );
        }
    }

    #[test]
    fn a_file_that_really_is_not_utf8_is_refused_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "latin1.md");
        let mut content = format!("caf\u{e9} {}\n", anthropic_key()).into_bytes();
        let at = content.iter().position(|b| *b == 0xC3).unwrap();
        content.splice(at..at + 2, [0xE9]); // the Latin-1 byte for é: not UTF-8
        write_old(&file, &content);
        let report = apply(&file, &dir.path().join("b"));
        assert!(report.entries.is_empty());
        assert!(report.errors.iter().any(|e| e.contains("not valid UTF-8")));
        assert!(std::fs::read(&file).unwrap() == content);
        let left: Vec<_> = std::fs::read_dir(dir.path().join("b")).unwrap().collect();
        assert!(
            left.is_empty(),
            "no backup of a file that was not changed: {left:?}"
        );
    }

    #[test]
    fn every_key_is_removed_however_many_there_are() {
        // One pass of the matcher collects at most 1000 hits from a text. 2,500 keys used to be
        // reported as "Redacted 1000", with 1,500 left in the file and no word about them.
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "many.md");
        let keys: Vec<String> = (0..2_500).map(github_token).collect();
        let content: String = keys.iter().map(|k| format!("token {k} end\n")).collect();
        write_old(&file, &content);

        let dry = redact_paths(std::slice::from_ref(&file), false, &dir.path().join("b"));
        assert_eq!(dry.total_secrets, 2_500);
        let report = apply(&file, &dir.path().join("b"));
        assert_eq!(report.total_secrets, 2_500, "{:?}", report.errors);
        assert_eq!(report.entries[0].secrets_remaining, 0);
        assert!(!report.unfinished());
        let after = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            after,
            format!("token {} end\n", secrets::REDACTION_PLACEHOLDER).repeat(2_500)
        );
    }

    #[test]
    fn a_deeply_nested_transcript_can_be_backed_up() {
        // A real layout: a sub-agent transcript whose own path is about 280 bytes. Flattening the
        // path into the backup's name made a name no filesystem accepts.
        let dir = tempfile::tempdir().unwrap();
        let file = dir
            .path()
            .join(".claude/projects")
            .join("-home-someone-Workspaces-customer-platform-services-payments-gateway-worktrees-feature-refactor-retry-logic")
            .join("11111111-2222-3333-4444-555555555555/subagents")
            .join(format!("agent-{}.jsonl", "a".repeat(180)));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        assert!(file.as_os_str().len() > 280);
        let key = github_token(11);
        write_old(&file, format!("{{\"m\":\"key {key}\"}}\n"));

        let report = apply(&file, &dir.path().join("b"));
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.total_secrets, 1);
        assert!(!std::fs::read_to_string(&file).unwrap().contains(&key));
        let backup = PathBuf::from(report.entries[0].backup_path.as_ref().unwrap());
        assert!(backup.file_name().unwrap().len() < 120);
        assert_eq!(
            std::fs::read_to_string(origin_record(&backup)).unwrap(),
            format!("{}\n", file.display()),
            "which file the backup is of is written down beside it"
        );
    }

    #[test]
    fn a_multiline_private_key_is_actually_redacted_not_just_reported() {
        // The critical bug: a PEM private key spans ~25 lines, so a line-at-a-time redactor never
        // matched it — the file was reported "redactable" and the key left on disk. Redacting the
        // window as one unit must actually remove it.
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "notes.md");
        let body: String = std::iter::repeat_n("QUFBQUFBQUFBQUFBQUFBQQ", 40)
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
        );
        write_old(
            &file,
            format!("# notes\nhere is a key:\n{pem}\ntrailing text\n"),
        );

        // Dry-run must count it (so the UI's "redactable" claim is honest)...
        let dry = redact_paths(std::slice::from_ref(&file), false, &dir.path().join("b"));
        assert!(
            dry.total_secrets >= 1,
            "dry-run must see the multi-line key"
        );

        // ...and apply must actually remove it from disk.
        let report = apply(&file, &dir.path().join("b"));
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

    #[test]
    fn a_key_is_never_cut_by_where_the_file_is_split() {
        // The file is rewritten in pieces. Wherever the pieces end, a key on one line, a key that
        // covers many lines, and a key whose rule needs a word before it must each come out
        // whole. Windows of a few hundred bytes put a split every few lines; the padding in front
        // moves every split across every position of the keys.
        let token = github_token(21);
        let body: String = std::iter::repeat_n("QUFBQUFBQUFBQUFBQUFBQQ", 6)
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
        );
        let whole_file = |pad: usize| {
            let mut text = String::new();
            text.push_str(&"p".repeat(pad));
            text.push('\n');
            for i in 0..12 {
                text.push_str(&format!("{{\"n\":{i},\"t\":\"filler filler filler\"}}\n"));
            }
            text.push_str(&format!("first {token} after\n{pem}\nmore lines\n"));
            for i in 0..12 {
                text.push_str(&format!("{{\"n\":{i},\"t\":\"filler filler filler\"}}\n"));
            }
            text.push_str(&format!("last line {token}\n"));
            text
        };
        let path = "/h/.claude/projects/p/s.md";
        let expected_count = secrets::redact_text_in(Some(path), &whole_file(0)).1;
        assert!(expected_count >= 3, "{expected_count}");
        for pad in 0..400 {
            let text = whole_file(pad);
            let (expected, _) = secrets::redact_text_in(Some(path), &text);
            let mut original = Vec::new();
            let mut redacted = String::new();
            let outcome =
                redact_stream_sized(&mut text.as_bytes(), path, 1024, 400, &mut |o, r| {
                    original.extend_from_slice(o);
                    redacted.push_str(r);
                    Ok(())
                })
                .unwrap();
            assert!(
                original == text.as_bytes(),
                "pad {pad}: the backup must be the file"
            );
            assert_eq!(outcome.count, expected_count, "pad {pad}");
            assert!(
                redacted == expected,
                "pad {pad}: split redaction differs from one pass"
            );
            assert_eq!(outcome.bytes, text.len() as u64);
        }
    }

    // ---- A file that is being written to.

    #[test]
    fn a_file_changed_moments_ago_is_left_alone_unless_told_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "live.jsonl");
        let key = github_token(31);
        let original = format!("{{\"m\":\"{key}\"}}\n");
        std::fs::write(&file, &original).unwrap(); // just now
        let backups = dir.path().join("b");

        let report = apply(&file, &backups);
        assert!(report.entries.is_empty());
        assert!(
            report.errors.iter().any(|e| e.contains(IN_USE)),
            "{:?}",
            report.errors
        );
        assert!(report.unfinished());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
        assert!(
            !backups.exists(),
            "nothing is copied for a file that is left alone"
        );
        // A preview is still given: it changes nothing.
        let dry = redact_paths(std::slice::from_ref(&file), false, &backups);
        assert_eq!(dry.total_secrets, 1);

        let opts = RedactOptions {
            apply: true,
            include_active: true,
        };
        let report = redact_with(std::slice::from_ref(&file), opts, &backups);
        assert_eq!(report.total_secrets, 1, "{:?}", report.errors);
        assert!(!std::fs::read_to_string(&file).unwrap().contains(&key));
    }

    fn append(path: &Path, line: &str) {
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(line.as_bytes()).unwrap();
    }

    const OPTS: RedactOptions = RedactOptions {
        apply: true,
        include_active: true,
    };

    #[test]
    fn lines_appended_while_a_file_is_being_rewritten_are_not_lost() {
        // The race, made exact: a session appends a line after the file was read and before it is
        // replaced. The rewrite used to rename its copy over the file, and the line was gone —
        // from the file and from the backup.
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "s.jsonl");
        let key = github_token(41);
        std::fs::write(&file, format!("{{\"n\":1}}\n{{\"m\":\"{key}\"}}\n")).unwrap();

        let mut appended = 0;
        let done = with_hook(
            move |stage, path| {
                if stage == "written" && appended == 0 {
                    appended += 1;
                    append(path, "{\"n\":\"appended during the read\"}\n");
                }
            },
            || {
                redact_one(&file, OPTS, &dir.path().join("b"))
                    .unwrap()
                    .unwrap()
            },
        );
        assert_eq!(done.entry.secrets_redacted, 1);
        assert!(done.notes.is_empty(), "{:?}", done.notes);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!(
                "{{\"n\":1}}\n{{\"m\":\"{}\"}}\n{{\"n\":\"appended during the read\"}}\n",
                secrets::REDACTION_PLACEHOLDER
            )
        );
        // The backup is of what was finally read, appended line included; the first try's backup
        // is gone.
        let backup = done.entry.backup_path.unwrap();
        assert!(std::fs::read_to_string(&backup)
            .unwrap()
            .ends_with("appended during the read\"}\n"));
        let kept: Vec<_> = std::fs::read_dir(dir.path().join("b"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(kept.len(), 2, "one backup and its path record: {kept:?}");
    }

    #[test]
    fn a_file_that_keeps_changing_is_refused_with_every_byte_intact() {
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "busy.jsonl");
        let key = github_token(42);
        let start = format!("{{\"m\":\"{key}\"}}\n");
        std::fs::write(&file, &start).unwrap();

        let mut n = 0;
        let err = with_hook(
            move |stage, path| {
                if stage == "written" {
                    n += 1;
                    append(path, &format!("{{\"n\":{n}}}\n"));
                }
            },
            || {
                redact_one(&file, OPTS, &dir.path().join("b"))
                    .err()
                    .expect("must refuse")
            },
        );
        assert!(err.to_string().contains("in use"), "{err}");
        assert!(err.to_string().contains(IN_USE), "{err}");
        // The original and everything appended to it, exactly; no temporary file beside it; no
        // backup kept for a rewrite that did not happen.
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!("{start}{{\"n\":1}}\n{{\"n\":2}}\n{{\"n\":3}}\n")
        );
        let beside: Vec<_> = std::fs::read_dir(file.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(beside, ["busy.jsonl"]);
        assert_eq!(std::fs::read_dir(dir.path().join("b")).unwrap().count(), 0);
    }

    #[test]
    fn a_line_written_at_the_instant_of_the_swap_is_carried_over() {
        // After the last look and before the rename there is still an instant. A line landing
        // there went to the old file; it is copied onto the end of the new one.
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "s.jsonl");
        let key = github_token(43);
        std::fs::write(&file, format!("{{\"m\":\"{key}\"}}\n")).unwrap();
        let done = with_hook(
            |stage, path| {
                if stage == "checked" {
                    append(path, "{\"n\":\"at the last instant\"}\n");
                }
            },
            || {
                redact_one(&file, OPTS, &dir.path().join("b"))
                    .unwrap()
                    .unwrap()
            },
        );
        assert!(done.notes.is_empty(), "{:?}", done.notes);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            format!(
                "{{\"m\":\"{}\"}}\n{{\"n\":\"at the last instant\"}}\n",
                secrets::REDACTION_PLACEHOLDER
            )
        );
    }

    #[test]
    fn a_file_replaced_under_its_name_is_not_overwritten() {
        // Something else swapped a different file in under the same name while this one was being
        // read. The copy that was made is of the old file: it must not replace the new one.
        let dir = tempfile::tempdir().unwrap();
        let file = agent_file(dir.path(), "s.jsonl");
        let key = github_token(44);
        std::fs::write(&file, format!("{{\"m\":\"{key}\"}}\n")).unwrap();
        let other_key = github_token(45);
        let replacement = format!("{{\"entirely\":\"different\",\"k\":\"{other_key}\"}}\n");
        let put = replacement.clone();
        let mut swaps = 0;
        let done = with_hook(
            move |stage, path| {
                if stage == "written" && swaps == 0 {
                    swaps += 1;
                    let other = path.with_extension("new");
                    std::fs::write(&other, &put).unwrap();
                    std::fs::rename(&other, path).unwrap();
                }
            },
            || {
                redact_one(&file, OPTS, &dir.path().join("b"))
                    .unwrap()
                    .unwrap()
            },
        );
        // It started again from the file that is there now: that file's key is gone, its other
        // content is intact, and the backup is of that file, not of the one it replaced.
        assert_eq!(done.entry.secrets_redacted, 1);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            replacement.replace(&other_key, secrets::REDACTION_PLACEHOLDER)
        );
        assert_eq!(
            std::fs::read_to_string(done.entry.backup_path.unwrap()).unwrap(),
            replacement
        );
    }
}
