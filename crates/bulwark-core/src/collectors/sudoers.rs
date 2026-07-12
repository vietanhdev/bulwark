use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct SudoersCollector;

/// One row per non-comment `/etc/sudoers`-style line, flagging `NOPASSWD` entries — a
/// privilege-escalation shortcut an attacker with any foothold on the account will look
/// for first (research report §4, HackTricks "SUDO and SUID").
pub fn parse_sudoers(text: &str, source: &str) -> Vec<Fact> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fact = Fact::new();
        fact.insert("source".to_string(), Value::String(source.to_string()));
        fact.insert("line".to_string(), Value::String(line.to_string()));
        fact.insert(
            "nopasswd".to_string(),
            Value::Bool(line.contains("NOPASSWD")),
        );
        rows.push(fact);
    }
    rows
}

impl Collector for SudoersCollector {
    fn name(&self) -> &'static str {
        "sudoers"
    }

    /// `/etc/sudoers` is normally `0440 root:root` — unreadable without elevation. This is
    /// exactly the collector the design doc's privileged path (§4, §8) exists for: skipped
    /// cleanly and reported as "N checks skipped (no privilege)" rather than erroring.
    fn requires_privilege(&self) -> bool {
        true
    }

    fn is_applicable(&self) -> bool {
        Path::new("/etc/sudoers").exists()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();
        let text = std::fs::read_to_string("/etc/sudoers")?;
        rows.extend(parse_sudoers(&text, "/etc/sudoers"));

        if let Ok(dir) = std::fs::read_dir("/etc/sudoers.d") {
            for entry in dir.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    rows.extend(parse_sudoers(&text, &path.display().to_string()));
                }
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_nopasswd_entries() {
        let text = "root ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) NOPASSWD: ALL\n";
        let rows = parse_sudoers(text, "/etc/sudoers");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get("nopasswd").unwrap(), &Value::Bool(false));
        assert_eq!(rows[1].get("nopasswd").unwrap(), &Value::Bool(true));
    }
}
