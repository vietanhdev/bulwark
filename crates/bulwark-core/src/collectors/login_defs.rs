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
pub fn parse_login_defs(text: &str) -> Fact {
    let mut fact = Fact::new();
    fact.insert(
        "sha_crypt_min_rounds_configured".to_string(),
        Value::Bool(false),
    );
    fact.insert("umask_configured".to_string(), Value::Bool(false));
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
            _ => {}
        }
    }
    fact
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
        Ok(vec![parse_login_defs(&text)])
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
}
