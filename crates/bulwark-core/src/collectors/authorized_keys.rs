use super::Collector;
use crate::models::Fact;
use serde_json::Value;

pub struct AuthorizedKeysCollector;

/// One row per key in an `authorized_keys`-format file. Doesn't attempt to parse the
/// `options` prefix some entries have (e.g. `command="...",no-pty ssh-ed25519 ...`) — v1
/// only reports key type, a short prefix of the key material, and the comment.
pub fn parse_authorized_keys(text: &str) -> Vec<Fact> {
    let mut rows = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(key_type_idx) = fields
            .iter()
            .position(|f| f.starts_with("ssh-") || f.starts_with("ecdsa-"))
        else {
            continue;
        };
        let key_type = fields[key_type_idx].to_string();
        let key_prefix: String = fields
            .get(key_type_idx + 1)
            .map(|k| k.chars().take(16).collect())
            .unwrap_or_default();
        let comment = fields[key_type_idx + 2..].join(" ");

        let mut fact = Fact::new();
        fact.insert("line_number".to_string(), Value::from(line_no + 1));
        fact.insert("key_type".to_string(), Value::String(key_type));
        fact.insert("key_prefix".to_string(), Value::String(key_prefix));
        fact.insert("comment".to_string(), Value::String(comment));
        rows.push(fact);
    }
    rows
}

impl Collector for AuthorizedKeysCollector {
    fn name(&self) -> &'static str {
        "authorized_keys"
    }

    fn is_applicable(&self) -> bool {
        Self::path().is_some()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let Some(path) = Self::path() else {
            return Ok(vec![]);
        };
        let text = std::fs::read_to_string(path)?;
        Ok(parse_authorized_keys(&text))
    }
}

impl AuthorizedKeysCollector {
    fn path() -> Option<std::path::PathBuf> {
        let home = std::env::var_os("HOME")?;
        let path = std::path::Path::new(&home).join(".ssh/authorized_keys");
        path.exists().then_some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_type_and_comment() {
        let text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@laptop\n";
        let rows = parse_authorized_keys(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("key_type").unwrap(), "ssh-ed25519");
        assert_eq!(rows[0].get("comment").unwrap(), "user@laptop");
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let text = "# a comment\n\nssh-rsa AAAAB3NzaC1yc2EAAAExample\n";
        let rows = parse_authorized_keys(text);
        assert_eq!(rows.len(), 1);
    }
}
