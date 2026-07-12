use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct LoggingCollector;

/// Whether audit logging exists at all, and whether logs leave the box — a purely
/// local-only log is erasable by the same root-level attacker it's meant to catch
/// (the exact limitation documented in the architecture doc §10).
pub fn detect_logging_state(auditd_present: bool, rsyslog_conf: Option<&str>) -> Fact {
    let mut fact = Fact::new();
    fact.insert("auditd_present".to_string(), Value::Bool(auditd_present));

    let forwards_remote = rsyslog_conf
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                .any(|l| l.contains('@'))
        })
        .unwrap_or(false);
    fact.insert(
        "rsyslog_forwards_remote".to_string(),
        Value::Bool(forwards_remote),
    );
    fact
}

impl Collector for LoggingCollector {
    fn name(&self) -> &'static str {
        "logging"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let auditd_present =
            Path::new("/sbin/auditd").exists() || Path::new("/usr/sbin/auditd").exists();
        let rsyslog_conf = std::fs::read_to_string("/etc/rsyslog.conf").ok();
        Ok(vec![detect_logging_state(
            auditd_present,
            rsyslog_conf.as_deref(),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_missing_auditd_and_local_only_logging() {
        let fact = detect_logging_state(false, Some("*.* /var/log/syslog\n"));
        assert_eq!(fact.get("auditd_present").unwrap(), &Value::Bool(false));
        assert_eq!(
            fact.get("rsyslog_forwards_remote").unwrap(),
            &Value::Bool(false)
        );
    }

    #[test]
    fn detects_remote_forwarding_rule() {
        let fact = detect_logging_state(true, Some("*.* @@logs.example.com:514\n"));
        assert_eq!(
            fact.get("rsyslog_forwards_remote").unwrap(),
            &Value::Bool(true)
        );
    }
}
