use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct LoginDefsCollector;

/// Parses `/etc/login.defs`-style `KEY value` lines relevant to password aging policy, plus
/// two presence-only settings (`SHA_CRYPT_MIN_ROUNDS`, `UMASK`) that Debian/Ubuntu leave
/// commented out by default — verified absent on this project's own dev machine. A rule
/// reading a numeric threshold on either would hit `MissingField` on most real systems (a
/// noisy collector_error every scan, not a real "misconfigured" reading), so instead of
/// numeric fields, these two are always-present booleans (`..._configured`) — "left at the
/// distro default" is itself the finding, and a boolean field can never be missing.
///
/// `umask_via_pam` folds in whether `pam_umask` is active in `/etc/pam.d` (see
/// [`pam_configures_umask`]): on modern Debian/Ubuntu the default umask is set through PAM, not
/// an explicit `UMASK` line, so treating a missing `login.defs` UMASK as "unconfigured" without
/// checking PAM is a false positive. `umask_configured` is therefore true when *either* source
/// sets it.
#[cfg(test)]
fn parse_login_defs(text: &str) -> Fact {
    build_fact(text, false)
}

fn build_fact(text: &str, umask_via_pam: bool) -> Fact {
    let mut fact = Fact::new();
    fact.insert(
        "sha_crypt_min_rounds_configured".to_string(),
        Value::Bool(false),
    );
    fact.insert("umask_configured".to_string(), Value::Bool(umask_via_pam));
    // Which crypt scheme new passwords use. SHA_CRYPT_MIN_ROUNDS only has any effect under the
    // sha256/sha512 schemes; under yescrypt or bcrypt (the modern Debian/Ubuntu default) it is
    // silently ignored, so a rule about it must not fire. Absent means "distro default", which on
    // current systems is yescrypt — so default to a method for which sha-crypt rounds do not apply.
    let mut encrypt_method = "unset".to_string();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default().trim();
        if value.is_empty() {
            continue;
        }
        match key {
            "PASS_MAX_DAYS" | "PASS_MIN_DAYS" | "PASS_WARN_AGE" | "PASS_MIN_LEN" => {
                if let Ok(n) = value.parse::<i64>() {
                    fact.insert(key.to_ascii_lowercase(), Value::from(n));
                }
            }
            "SHA_CRYPT_MIN_ROUNDS" => {
                fact.insert(
                    "sha_crypt_min_rounds_configured".to_string(),
                    Value::Bool(true),
                );
            }
            "UMASK" => {
                fact.insert("umask_configured".to_string(), Value::Bool(true));
            }
            "ENCRYPT_METHOD" => {
                encrypt_method = value.to_ascii_lowercase();
            }
            _ => {}
        }
    }
    // SHA_CRYPT_MIN_ROUNDS is actionable only when the hashing scheme actually consults it.
    let sha_crypt_applies = matches!(encrypt_method.as_str(), "sha256" | "sha512");
    fact.insert("encrypt_method".to_string(), Value::from(encrypt_method));
    fact.insert(
        "sha_crypt_applies".to_string(),
        Value::Bool(sha_crypt_applies),
    );
    fact
}

/// True if any active (uncommented) line across the `/etc/pam.d` session stacks pulls in
/// `pam_umask` — the mechanism that sets the default umask on modern Debian/Ubuntu, where
/// `login.defs` carries no explicit `UMASK`.
fn pam_configures_umask(pam_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(pam_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if text
            .lines()
            .map(str::trim)
            .any(|l| !l.starts_with('#') && l.contains("pam_umask"))
        {
            return true;
        }
    }
    false
}

impl Collector for LoginDefsCollector {
    fn name(&self) -> &'static str {
        "login_defs"
    }

    fn is_applicable(&self) -> bool {
        Path::new("/etc/login.defs").exists()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let text = std::fs::read_to_string("/etc/login.defs")?;
        let umask_via_pam = pam_configures_umask(Path::new("/etc/pam.d"));
        Ok(vec![build_fact(&text, umask_via_pam)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_password_aging_fields() {
        let text = "# comment\nPASS_MAX_DAYS\t99999\nPASS_MIN_LEN\t8\n";
        let fact = parse_login_defs(text);
        assert_eq!(fact.get("pass_max_days").unwrap(), &Value::from(99999));
        assert_eq!(fact.get("pass_min_len").unwrap(), &Value::from(8));
    }

    #[test]
    fn sha_crypt_and_umask_default_to_not_configured() {
        // The real, distro-default case (verified absent on this project's own dev machine)
        // — must read as a defined `false`, never as a missing field a rule would error on.
        let fact = parse_login_defs("PASS_MAX_DAYS\t99999\n");
        assert_eq!(
            fact.get("sha_crypt_min_rounds_configured").unwrap(),
            &Value::Bool(false)
        );
        assert_eq!(fact.get("umask_configured").unwrap(), &Value::Bool(false));
    }

    #[test]
    fn detects_sha_crypt_and_umask_when_present() {
        let text = "SHA_CRYPT_MIN_ROUNDS\t5000\nUMASK\t027\n";
        let fact = parse_login_defs(text);
        assert_eq!(
            fact.get("sha_crypt_min_rounds_configured").unwrap(),
            &Value::Bool(true)
        );
        assert_eq!(fact.get("umask_configured").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn sha_crypt_applies_only_under_sha_schemes() {
        // yescrypt (the modern default): SHA_CRYPT_MIN_ROUNDS is ignored, so the rule must not fire.
        let yescrypt = parse_login_defs("ENCRYPT_METHOD YESCRYPT\n");
        assert_eq!(
            yescrypt.get("sha_crypt_applies").unwrap(),
            &Value::Bool(false)
        );
        assert_eq!(
            yescrypt.get("encrypt_method").unwrap(),
            &Value::from("yescrypt")
        );

        // Absent ENCRYPT_METHOD → distro default is yescrypt today; do not flag (avoid the FP).
        let unset = parse_login_defs("PASS_MAX_DAYS 99999\n");
        assert_eq!(unset.get("sha_crypt_applies").unwrap(), &Value::Bool(false));

        // sha512: the one case where SHA_CRYPT_MIN_ROUNDS is actionable.
        let sha = parse_login_defs("ENCRYPT_METHOD SHA512\n");
        assert_eq!(sha.get("sha_crypt_applies").unwrap(), &Value::Bool(true));
        // And with it unset, the rule's precondition (applies && !configured) holds.
        assert_eq!(
            sha.get("sha_crypt_min_rounds_configured").unwrap(),
            &Value::Bool(false)
        );
    }

    #[test]
    fn pam_umask_counts_as_configured_even_without_a_login_defs_line() {
        // No UMASK in login.defs, but pam_umask is active → umask IS configured (not a finding).
        let fact = build_fact("PASS_MAX_DAYS 99999\n", /*umask_via_pam=*/ true);
        assert_eq!(fact.get("umask_configured").unwrap(), &Value::Bool(true));
        // Neither source configures it → the finding stands.
        let bare = build_fact("PASS_MAX_DAYS 99999\n", false);
        assert_eq!(bare.get("umask_configured").unwrap(), &Value::Bool(false));
    }

    #[test]
    fn pam_configures_umask_reads_a_real_pam_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("common-session"),
            "session optional pam_umask.so\n",
        )
        .unwrap();
        assert!(pam_configures_umask(dir.path()));

        // A commented-out reference does not count.
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(
            dir2.path().join("common-session"),
            "# session pam_umask.so\n",
        )
        .unwrap();
        assert!(!pam_configures_umask(dir2.path()));
    }
}
