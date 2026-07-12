use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;

pub struct FilePermissionsCollector;

/// Sensitive paths worth a per-file permission check — the exact set AIDE/Wazuh FIM would
/// baseline (research report §7): auth config, credential stores, persistence surfaces.
const WATCHED: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
];

/// Given a file's mode bits, reports whether it's group- or world-writable — the actual
/// exploitable condition, not just "not 600" (some of these are legitimately 644).
pub fn describe_mode(path: &str, mode: u32) -> Fact {
    let mut fact = Fact::new();
    fact.insert("path".to_string(), Value::String(path.to_string()));
    fact.insert(
        "mode_octal".to_string(),
        Value::String(format!("{:o}", mode & 0o777)),
    );
    fact.insert("world_writable".to_string(), Value::Bool(mode & 0o002 != 0));
    fact.insert("group_writable".to_string(), Value::Bool(mode & 0o020 != 0));
    fact.insert("world_readable".to_string(), Value::Bool(mode & 0o004 != 0));
    fact
}

impl Collector for FilePermissionsCollector {
    fn name(&self) -> &'static str {
        "file_permissions"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();
        for path in WATCHED {
            // A watched path that doesn't exist on this distro (e.g. no /etc/sudoers on a
            // machine that only uses /etc/sudoers.d) is skipped, not an error — existence
            // varies legitimately across distros.
            if let Ok(meta) = std::fs::metadata(path) {
                rows.push(describe_mode(path, meta.permissions().mode()));
            }
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_world_writable() {
        let fact = describe_mode("/etc/shadow", 0o100646);
        assert_eq!(fact.get("world_writable").unwrap(), &Value::Bool(true));
        assert_eq!(fact.get("mode_octal").unwrap(), "646");
    }

    #[test]
    fn normal_permissions_are_not_flagged() {
        let fact = describe_mode("/etc/shadow", 0o100640);
        assert_eq!(fact.get("world_writable").unwrap(), &Value::Bool(false));
        assert_eq!(fact.get("world_readable").unwrap(), &Value::Bool(false));
    }
}
