use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct SshdConfigCollector;

/// sshd_config directives are CamelCase (`PasswordAuthentication`); rule conditions read
/// snake_case (`password_authentication`) for consistency with every other collector's
/// field names. This converts one to the other — a plain `.to_ascii_lowercase()` would
/// collapse `PasswordAuthentication` into `passwordauthentication` with no separator,
/// silently breaking every rule that reads it (caught by this module's own tests).
fn to_snake_case(directive: &str) -> String {
    let mut out = String::with_capacity(directive.len() + 4);
    for (i, c) in directive.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// Parses sshd_config-style `Key Value` lines into a flat, snake_case-keyed fact map.
/// Exposed standalone so it can be unit-tested against fixture text without touching disk.
pub fn parse_sshd_config(text: &str) -> Fact {
    let mut fact = Fact::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let key = to_snake_case(parts.next().unwrap_or_default());
        let value = parts.next().unwrap_or_default().trim().to_string();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        // Later directives win, matching sshd's own "first match wins per Match block"
        // being out of scope for v1 — we intentionally don't model Match blocks yet.
        //
        // A purely-numeric directive value (MaxAuthTries, ClientAliveInterval, Port, ...)
        // is stored as a JSON number, not a string, so rules can use the condition DSL's
        // numeric `>`/`<` thresholds on it — matching how sysctl_kernel already stores its
        // values. Everything else (yes/no, prohibit-password, cipher lists, ...) stays a
        // lowercased string, same as before.
        let parsed = value
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::String(value.to_ascii_lowercase()));
        fact.entry(key).or_insert(parsed);
    }
    fact
}

impl Collector for SshdConfigCollector {
    fn name(&self) -> &'static str {
        "sshd_config"
    }

    fn is_applicable(&self) -> bool {
        Path::new("/etc/ssh/sshd_config").exists()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let text = std::fs::read_to_string("/etc/ssh/sshd_config")?;
        Ok(vec![parse_sshd_config(&text)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_directives() {
        let text =
            "PasswordAuthentication yes\nPermitRootLogin no\n# comment\nPermitEmptyPasswords no\n";
        let fact = parse_sshd_config(text);
        assert_eq!(fact.get("password_authentication").unwrap(), "yes");
        assert_eq!(fact.get("permit_root_login").unwrap(), "no");
        assert_eq!(fact.get("permit_empty_passwords").unwrap(), "no");
    }

    #[test]
    fn snake_case_conversion_matches_rule_field_names() {
        assert_eq!(
            to_snake_case("PasswordAuthentication"),
            "password_authentication"
        );
        assert_eq!(to_snake_case("PermitRootLogin"), "permit_root_login");
        assert_eq!(
            to_snake_case("PermitEmptyPasswords"),
            "permit_empty_passwords"
        );
    }

    #[test]
    fn ignores_blank_and_comment_lines() {
        let text = "\n# just a comment\n   \nPasswordAuthentication yes\n";
        let fact = parse_sshd_config(text);
        assert_eq!(fact.len(), 1);
    }

    #[test]
    fn numeric_directives_are_stored_as_numbers_not_strings() {
        // Needed so rule conditions can use numeric thresholds (e.g. `max_auth_tries > 6`)
        // on directives like MaxAuthTries — regression test for the coercion added
        // alongside the Lynis-derived SSH-004..011 rule pack.
        let text = "MaxAuthTries 999\nPort 22\nPermitRootLogin no\n";
        let fact = parse_sshd_config(text);
        assert_eq!(fact.get("max_auth_tries").unwrap(), &Value::from(999));
        assert_eq!(fact.get("port").unwrap(), &Value::from(22));
        // Non-numeric values are unaffected — still lowercased strings.
        assert_eq!(fact.get("permit_root_login").unwrap(), "no");
    }
}
