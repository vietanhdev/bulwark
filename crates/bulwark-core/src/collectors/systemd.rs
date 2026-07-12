use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct SystemdUnitsCollector;

/// Extracts the fields a persistence-detection rule cares about from one `.service` unit
/// file's text: its ExecStart/ExecStartPost lines, concatenated so a `contains`/`matches`
/// condition can scan both without the rule author needing to know which directive it's in.
pub fn parse_unit_file(unit_name: &str, text: &str) -> Fact {
    let mut fact = Fact::new();
    fact.insert(
        "unit_name".to_string(),
        Value::String(unit_name.to_string()),
    );

    let mut exec_lines = Vec::new();
    let mut enabled_hint = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ExecStart=") {
            exec_lines.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("ExecStartPost=") {
            exec_lines.push(rest.to_string());
        } else if line.starts_with("WantedBy=") {
            enabled_hint = true;
        }
    }
    fact.insert(
        "exec_start".to_string(),
        Value::String(exec_lines.join(" ; ")),
    );
    fact.insert("has_install_section".to_string(), Value::Bool(enabled_hint));
    fact
}

impl Collector for SystemdUnitsCollector {
    fn name(&self) -> &'static str {
        "systemd_units"
    }

    fn is_applicable(&self) -> bool {
        Path::new("/etc/systemd/system").is_dir()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();
        let dir = std::fs::read_dir("/etc/systemd/system")?;
        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("service") {
                continue;
            }
            let unit_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            // A unit file that's a broken symlink (removed persistence, left dangling) is
            // reported as a collector error rather than silently skipped.
            match std::fs::read_to_string(&path) {
                Ok(text) => rows.push(parse_unit_file(&unit_name, &text)),
                Err(e) => {
                    return Err(anyhow::anyhow!("reading {}: {}", path.display(), e));
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
    fn extracts_exec_start_and_post() {
        let text = "[Unit]\nDescription=x\n[Service]\nExecStart=/usr/bin/ngrok tcp 22\nExecStartPost=/bin/bash -c 'curl https://api.telegram.org'\n[Install]\nWantedBy=multi-user.target\n";
        let fact = parse_unit_file("ngrok-ssh.service", text);
        let exec = fact.get("exec_start").unwrap().as_str().unwrap();
        assert!(exec.contains("ngrok"));
        assert!(exec.contains("curl"));
        assert_eq!(fact.get("has_install_section").unwrap(), &Value::Bool(true));
    }
}
