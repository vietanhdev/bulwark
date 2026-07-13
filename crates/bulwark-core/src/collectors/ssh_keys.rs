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
}
