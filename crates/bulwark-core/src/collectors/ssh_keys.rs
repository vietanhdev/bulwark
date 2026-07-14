//! Reports whether the SSH **private** keys in the invoking user's `~/.ssh` are protected by a
//! passphrase. An unencrypted private key is a plaintext credential sitting on disk: anyone who
//! reads the file — a backup that leaked, a stolen laptop, a malicious process running as the
//! user, a synced dotfiles repo — can use it directly, with no passphrase to stop them. A
//! passphrase turns that single file into something an attacker must also crack.
//!
//! Encryption status is determined from the key file's *header only* — no passphrase is needed,
//! and this collector never reads, stores, or reports any key material, only the path, the key
//! format, and a single `encrypted` boolean. Three on-disk formats are recognized:
//!   * new OpenSSH (`BEGIN OPENSSH PRIVATE KEY`) — the cipher name is embedded near the start of
//!     the base64 blob; `none` means unencrypted, anything else means encrypted.
//!   * legacy PEM (`BEGIN RSA/EC/DSA PRIVATE KEY`) — encrypted keys carry a `Proc-Type: 4,ENCRYPTED`
//!     header; without it the key body is plaintext.
//!   * PKCS#8 (`BEGIN [ENCRYPTED] PRIVATE KEY`) — the `ENCRYPTED` variant is passphrase-protected.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct SshPrivateKeysCollector;

/// Filenames in `~/.ssh` that are never private keys, so we don't waste a read or risk a
/// false classification on them. Public keys, the client config, and the host/authorized-key
/// databases are all excluded; anything else is classified by its actual content header.
fn is_never_a_private_key(name: &str) -> bool {
    name.ends_with(".pub")
        || matches!(
            name,
            "known_hosts" | "known_hosts.old" | "authorized_keys" | "authorized_keys2" | "config"
        )
}

fn ssh_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let dir = Path::new(&home).join(".ssh");
    dir.is_dir().then_some(dir)
}

/// `Some((format, encrypted))` if `content` is a recognizable SSH private key, else `None`.
///
/// `encrypted` is three-state: `Some(true)` known passphrase-protected, `Some(false)` known
/// plaintext, `None` **undetermined** — the encryption status could not be read from the header.
/// Undetermined must never be collapsed to a confident answer: reporting it as encrypted would
/// hide a plaintext key (a false clean), reporting it as plaintext would cry wolf on a key we
/// couldn't actually read. The collector surfaces the third state via `encryption_known` so a rule
/// can flag "couldn't verify" separately from "verified unencrypted".
pub fn classify_private_key(content: &str) -> Option<(&'static str, Option<bool>)> {
    if content.contains("BEGIN OPENSSH PRIVATE KEY") {
        // `none` cipher → plaintext; any other cipher → encrypted; unreadable header → undetermined.
        let encrypted = openssh_cipher(content).map(|c| c != "none");
        return Some(("openssh", encrypted));
    }
    if content.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        return Some(("pkcs8", Some(true)));
    }
    if content.contains("BEGIN PRIVATE KEY") {
        return Some(("pkcs8", Some(false)));
    }
    if content.contains("PRIVATE KEY-----") && content.contains("BEGIN") {
        // Legacy PEM (RSA/EC/DSA). Encrypted keys carry the classic `Proc-Type: 4,ENCRYPTED` +
        // `DEK-Info:` headers; without them the key body is plaintext.
        let encrypted = content.contains("Proc-Type:") && content.contains("ENCRYPTED");
        return Some(("pem", Some(encrypted)));
    }
    None
}

/// Reads the cipher name embedded in a new-format OpenSSH private key. The decoded blob is:
/// `"openssh-key-v1\0"` (15 bytes), then a big-endian u32 length, then that many bytes of cipher
/// name (`"none"` for an unencrypted key). Only the first handful of base64 characters need
/// decoding, so this stops well before the key material.
fn openssh_cipher(content: &str) -> Option<String> {
    let b64: String = content
        .lines()
        .skip_while(|l| !l.contains("BEGIN OPENSSH PRIVATE KEY"))
        .skip(1)
        .take_while(|l| !l.contains("END OPENSSH PRIVATE KEY"))
        .flat_map(|l| l.trim().chars())
        .collect();

    // 15 (magic) + 4 (len) + up to ~20 (cipher name) bytes is plenty; decode a bounded prefix.
    let bytes = base64_decode_prefix(&b64, 64)?;
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    if bytes.len() < MAGIC.len() + 4 || &bytes[..MAGIC.len()] != MAGIC {
        return None;
    }
    let len_at = MAGIC.len();
    let len = u32::from_be_bytes([
        bytes[len_at],
        bytes[len_at + 1],
        bytes[len_at + 2],
        bytes[len_at + 3],
    ]) as usize;
    let start = len_at + 4;
    let end = start.checked_add(len)?;
    if end > bytes.len() || len > 64 {
        return None;
    }
    String::from_utf8(bytes[start..end].to_vec()).ok()
}

/// Decodes at most `max_bytes` bytes from the standard-alphabet base64 in `input`, ignoring any
/// characters outside the alphabet (newlines, stray whitespace). Padding is irrelevant because we
/// only ever want a prefix. Deliberately tiny and dependency-free — it decodes a key *header*, not
/// arbitrary data.
fn base64_decode_prefix(input: &str, max_bytes: usize) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in input.as_bytes() {
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            if out.len() >= max_bytes {
                break;
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

impl SshPrivateKeysCollector {
    fn private_key_facts(dir: &Path) -> Vec<Fact> {
        let mut facts = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return facts;
        };
        for entry in entries.flatten() {
            // Skip symlinks (don't follow one out of ~/.ssh) and non-files by dirent type.
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() || !ft.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if is_never_a_private_key(&name) {
                continue;
            }
            let Ok(content) = super::read_capped(&entry.path()) else {
                continue;
            };
            let Some((format, encrypted)) = classify_private_key(&content) else {
                continue;
            };
            let mut fact = Fact::new();
            // Path and metadata only — never any bytes of the key itself.
            fact.insert(
                "path".to_string(),
                Value::String(entry.path().display().to_string()),
            );
            fact.insert("key_format".to_string(), Value::String(format.to_string()));
            // Three-state, per the collector invariant: `encryption_known` distinguishes "we read
            // the header and it's plaintext" (a real finding) from "we couldn't read the header"
            // (undetermined). On undetermined we emit `encrypted: false` but `encryption_known:
            // false`, so the passphrase rule (which requires encryption_known) does NOT fire — a
            // key we couldn't verify is never reported as protected, nor as a confirmed plaintext.
            fact.insert(
                "encrypted".to_string(),
                Value::Bool(encrypted.unwrap_or(false)),
            );
            fact.insert(
                "encryption_known".to_string(),
                Value::Bool(encrypted.is_some()),
            );
            facts.push(fact);
        }
        facts
    }
}

impl Collector for SshPrivateKeysCollector {
    fn name(&self) -> &'static str {
        "ssh_private_keys"
    }

    fn is_applicable(&self) -> bool {
        ssh_dir().is_some()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let Some(dir) = ssh_dir() else {
            return Ok(vec![]);
        };
        Ok(Self::private_key_facts(&dir))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Remediation: add one passphrase to every unencrypted key, in one pass.
// ─────────────────────────────────────────────────────────────────────────────

/// What happened to one key when [`protect_unencrypted_keys`] ran.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum KeyProtectionOutcome {
    /// Was confidently unencrypted; is now passphrase-protected.
    Protected,
    /// Already encrypted — left untouched.
    AlreadyEncrypted,
    /// Encryption status could not be read from the header — left untouched, never guessed.
    Undetermined,
    /// The attempt errored; the key was restored from its backup and is unchanged.
    Failed { reason: String },
}

/// Per-key result. `backup_path` is set only when the key was actually modified (or an attempt
/// was made and then rolled back).
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyProtectionResult {
    pub path: String,
    pub key_format: String,
    pub outcome: KeyProtectionOutcome,
    pub backup_path: Option<String>,
}

/// Summary of a bulk protect run.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BulkProtectionReport {
    pub results: Vec<KeyProtectionResult>,
    pub protected: usize,
    pub already_encrypted: usize,
    pub undetermined: usize,
    pub failed: usize,
}

/// Adds a single `passphrase` to every SSH private key in `~/.ssh` that is *confidently*
/// unencrypted, in one pass — a single password for the whole set, which is far better than
/// leaving plaintext keys on disk. Keys that are already encrypted, or whose status can't be read
/// from the header, are left untouched: this never weakens a key and never guesses.
///
/// Safety:
///   * Symlinks are refused (a symlink in `~/.ssh` could otherwise redirect `ssh-keygen` onto an
///     arbitrary file). Only regular files are touched.
///   * Every key is copied to a `0600` backup under `backup_dir` before it is modified, and
///     restored from that backup if the rewrite or the post-check fails — so a key is never left
///     half-converted.
///   * The passphrase is handed to `ssh-keygen` through an `SSH_ASKPASS` helper that reads it from
///     an environment variable, **never** through argv. `/proc/<pid>/cmdline` (where argv lands) is
///     world-readable; `/proc/<pid>/environ` is readable only by the file's owner, who already
///     knows the passphrase. The child is also detached from any controlling TTY so `ssh-keygen`
///     uses askpass rather than prompting on `/dev/tty`.
///   * After each conversion the key's header is re-read and re-classified; if it did not actually
///     become encrypted (e.g. a silent askpass fallback), the change is rolled back and reported as
///     a failure rather than a false success.
pub fn protect_unencrypted_keys(
    passphrase: &str,
    backup_dir: &Path,
) -> anyhow::Result<BulkProtectionReport> {
    if passphrase.is_empty() {
        anyhow::bail!("refusing to set an empty passphrase — that would leave the key unprotected");
    }
    let Some(dir) = ssh_dir() else {
        return Ok(BulkProtectionReport::default());
    };
    protect_keys_in_dir(&dir, passphrase, backup_dir)
}

/// The directory-scoped core of [`protect_unencrypted_keys`], split out so it can be tested against
/// a temp `.ssh` without racing on the process-global `HOME`.
fn protect_keys_in_dir(
    dir: &Path,
    passphrase: &str,
    backup_dir: &Path,
) -> anyhow::Result<BulkProtectionReport> {
    let mut report = BulkProtectionReport::default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(report);
    };

    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        // Same discipline as the collector: never follow a symlink out of ~/.ssh, only touch
        // regular files, and skip names that are never private keys (.pub, known_hosts, config).
        if ft.is_symlink() || !ft.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if is_never_a_private_key(&name) {
            continue;
        }
        let path = entry.path();
        let Ok(content) = super::read_capped(&path) else {
            continue;
        };
        let Some((format, encrypted)) = classify_private_key(&content) else {
            continue; // not a private key
        };

        let mut result = KeyProtectionResult {
            path: path.display().to_string(),
            key_format: format.to_string(),
            outcome: KeyProtectionOutcome::Protected,
            backup_path: None,
        };
        match encrypted {
            Some(true) => {
                result.outcome = KeyProtectionOutcome::AlreadyEncrypted;
                report.already_encrypted += 1;
            }
            None => {
                result.outcome = KeyProtectionOutcome::Undetermined;
                report.undetermined += 1;
            }
            Some(false) => match add_passphrase_with_backup(&path, passphrase, backup_dir) {
                Ok(backup) => {
                    result.backup_path = Some(backup.display().to_string());
                    report.protected += 1;
                }
                Err(e) => {
                    result.outcome = KeyProtectionOutcome::Failed {
                        reason: e.to_string(),
                    };
                    report.failed += 1;
                }
            },
        }
        report.results.push(result);
    }
    Ok(report)
}

/// Backs up `key` (0600), adds the passphrase, then verifies the key really became encrypted —
/// rolling back from the backup on any failure. Returns the backup path on success.
fn add_passphrase_with_backup(
    key: &Path,
    passphrase: &str,
    backup_dir: &Path,
) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(backup_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(backup_dir, std::fs::Permissions::from_mode(0o700));
    }
    let original = std::fs::read(key)?;
    let backup = backup_target(key, backup_dir);
    write_owner_only(&backup, &original)?;

    let restore = || {
        // Best-effort rollback: put the original bytes back so a failed attempt never leaves a
        // half-converted or damaged key on disk.
        let _ = std::fs::write(key, &original);
    };

    if let Err(e) = run_ssh_keygen_add_passphrase(key, passphrase) {
        restore();
        return Err(e);
    }

    // Confirm it actually encrypted — re-read the header and re-classify. A silent askpass fallback
    // could otherwise "succeed" while leaving the key plaintext or empty-passphrased.
    let now = super::read_capped(key).unwrap_or_default();
    match classify_private_key(&now) {
        Some((_, Some(true))) => Ok(backup),
        _ => {
            restore();
            anyhow::bail!("key did not become encrypted after ssh-keygen ran; rolled back")
        }
    }
}

/// Runs `ssh-keygen -p` to set a new passphrase on an already-unencrypted key, feeding the
/// passphrase through `SSH_ASKPASS` + an environment variable (never argv — see
/// [`protect_unencrypted_keys`]).
#[cfg(unix)]
fn run_ssh_keygen_add_passphrase(key: &Path, passphrase: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    // A tiny helper that prints the passphrase from the environment. The SCRIPT bytes carry no
    // secret — only a reference to the env var — so the temp file is inert if read.
    let helper = std::env::temp_dir().join(format!(
        ".bulwark-askpass-{}",
        std::process::id() // one per process; removed right after the run
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&helper)?;
        f.write_all(b"#!/bin/sh\nexec printf %s \"$BULWARK_SSH_NEW_PP\"\n")?;
    }
    // Remove the helper no matter how we exit.
    struct RemoveOnDrop(PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = RemoveOnDrop(helper.clone());

    let mut cmd = Command::new("ssh-keygen");
    cmd.arg("-p")
        .arg("-f")
        .arg(key)
        .arg("-P")
        .arg("") // old passphrase is empty (the key is unencrypted); "" is not sensitive
        .env("SSH_ASKPASS", &helper)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("BULWARK_SSH_NEW_PP", passphrase)
        .env_remove("DISPLAY")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // New session → no controlling TTY, so ssh-keygen takes the passphrase from askpass rather than
    // trying to prompt on /dev/tty (which would hang or fall back unpredictably).
    // SAFETY: `setsid` runs in the forked child before exec and touches no shared state; failure is
    // non-fatal (`SSH_ASKPASS_REQUIRE=force` still routes to askpass), so the return is ignored.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let output = cmd.output()?;

    if !output.status.success() {
        anyhow::bail!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn run_ssh_keygen_add_passphrase(_key: &Path, _passphrase: &str) -> anyhow::Result<()> {
    anyhow::bail!("adding an SSH key passphrase is only supported on Unix")
}

/// A collision-safe `.bak` path for `key` under `backup_dir`.
fn backup_target(key: &Path, backup_dir: &Path) -> PathBuf {
    let stem = key
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

/// Writes `bytes` to a freshly created `0600` file (`O_EXCL | O_NOFOLLOW`) — the backup of a
/// private key must never have even a brief group/world-readable window.
#[cfg(unix)]
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unencrypted_openssh_key_is_detected() {
        // A real `ssh-keygen -t ed25519 -N ""` header: magic + cipher "none". Only the first
        // base64 block is needed; the rest is elided (the decoder stops after the header).
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                   b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n\
                   -----END OPENSSH PRIVATE KEY-----\n";
        assert_eq!(classify_private_key(key), Some(("openssh", Some(false))));
    }

    #[test]
    fn an_openssh_key_with_an_unreadable_header_is_undetermined_not_encrypted() {
        // Garbage where the cipher header should be: we cannot tell if it's protected. The old code
        // defaulted this to `encrypted: true`, silently clearing the passphrase rule and hiding a
        // possibly-plaintext key. It must now come back undetermined (None), never a confident true.
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                   bm90LXZhbGlkLWhlYWRlcg==\n\
                   -----END OPENSSH PRIVATE KEY-----\n";
        assert_eq!(classify_private_key(key), Some(("openssh", None)));
    }

    #[test]
    fn encrypted_openssh_key_is_detected() {
        // Header for a real passphrase-protected key: magic + u32 length 10 + cipher "aes256-ctr".
        // This exercises the positive cipher-parse path (a non-"none" cipher name read out of the
        // decoded header), not just the encrypted-by-default fallback.
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                   b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHI=\n\
                   -----END OPENSSH PRIVATE KEY-----\n";
        assert_eq!(openssh_cipher(key).as_deref(), Some("aes256-ctr"));
        assert_eq!(classify_private_key(key), Some(("openssh", Some(true))));
    }

    #[test]
    fn legacy_pem_encrypted_vs_plain() {
        let plain = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(classify_private_key(plain), Some(("pem", Some(false))));

        let enc = "-----BEGIN RSA PRIVATE KEY-----\n\
                   Proc-Type: 4,ENCRYPTED\n\
                   DEK-Info: AES-128-CBC,0123\n\n\
                   MIIEow...\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(classify_private_key(enc), Some(("pem", Some(true))));
    }

    #[test]
    fn pkcs8_encrypted_vs_plain() {
        let plain = "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n";
        assert_eq!(classify_private_key(plain), Some(("pkcs8", Some(false))));
        let enc =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB...\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert_eq!(classify_private_key(enc), Some(("pkcs8", Some(true))));
    }

    #[test]
    fn non_key_content_is_ignored() {
        assert_eq!(classify_private_key("just some notes\n"), None);
        assert_eq!(
            classify_private_key("ssh-ed25519 AAAAC3... user@host\n"),
            None
        );
    }

    #[test]
    fn public_keys_and_config_are_never_private_keys() {
        assert!(is_never_a_private_key("id_ed25519.pub"));
        assert!(is_never_a_private_key("known_hosts"));
        assert!(is_never_a_private_key("config"));
        assert!(!is_never_a_private_key("id_ed25519"));
    }

    #[test]
    fn protect_refuses_an_empty_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let err = protect_unencrypted_keys("", dir.path()).unwrap_err();
        assert!(err.to_string().contains("empty passphrase"));
    }

    #[cfg(unix)]
    fn ssh_keygen_available() -> bool {
        std::process::Command::new("ssh-keygen")
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|_| true) // `--help` exits non-zero but proves the binary runs
            .unwrap_or(false)
    }

    #[cfg(unix)]
    #[test]
    fn protects_an_unencrypted_key_and_leaves_an_encrypted_one_alone() {
        if !ssh_keygen_available() {
            eprintln!("ssh-keygen not installed; skipping");
            return;
        }
        use std::process::Command;
        let ssh = tempfile::tempdir().unwrap();
        let backups = tempfile::tempdir().unwrap();

        // One plaintext key (the target) and one already-protected key (must be left untouched).
        let plain = ssh.path().join("id_plain");
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-q", "-f"])
            .arg(&plain)
            .status()
            .unwrap();
        let already = ssh.path().join("id_locked");
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "existing-pass", "-q", "-f"])
            .arg(&already)
            .status()
            .unwrap();

        // Both start classified as expected.
        assert_eq!(
            classify_private_key(&std::fs::read_to_string(&plain).unwrap()),
            Some(("openssh", Some(false)))
        );

        let report = protect_keys_in_dir(ssh.path(), "one-pass-for-all", backups.path()).unwrap();
        assert_eq!(
            report.protected, 1,
            "exactly the plaintext key is protected"
        );
        assert_eq!(
            report.already_encrypted, 1,
            "the encrypted key is left alone"
        );
        assert_eq!(report.failed, 0);

        // The plaintext key is now genuinely encrypted...
        assert_eq!(
            classify_private_key(&std::fs::read_to_string(&plain).unwrap()),
            Some(("openssh", Some(true))),
            "the target key is now passphrase-protected"
        );
        // ...it rejects the wrong passphrase and accepts the one we set...
        assert!(
            !Command::new("ssh-keygen")
                .arg("-y")
                .arg("-f")
                .arg(&plain)
                .args(["-P", "wrong"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success(),
            "the new passphrase actually took (wrong one is rejected)"
        );
        assert!(Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&plain)
            .args(["-P", "one-pass-for-all"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success());

        // ...and a 0600 backup of the original was written.
        let protected = report
            .results
            .iter()
            .find(|r| r.outcome == KeyProtectionOutcome::Protected)
            .unwrap();
        let backup = protected.backup_path.as_ref().unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600,
            "the key backup must be owner-only"
        );
    }
}
