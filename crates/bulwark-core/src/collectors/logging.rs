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
                .any(|l| {
                    // Three ways rsyslog is told to forward off-box, and real configs use all of
                    // them: the classic `@host`/`@@host` sugar, the `omfwd` output module, and the
                    // modern `action(type="omfwd" target="…")` object syntax. Checking only for
                    // `@` (as the first version did) misses the two module forms entirely — and
                    // those are what a modern drop-in under /etc/rsyslog.d most often uses.
                    l.contains('@')
                        || l.contains("omfwd")
                        || (l.contains("action(") && l.contains("target"))
                })
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
        // rsyslog's config is a directory, not a file: /etc/rsyslog.conf pulls in
        // /etc/rsyslog.d/*.conf, and remote-forwarding rules almost always live in a drop-in
        // there (e.g. a 60-remote.conf shipped by a log-shipper package), not in the main file.
        // Reading only /etc/rsyslog.conf reported "logs are not forwarded" on a host that forwards
        // via a drop-in — a false positive. Concatenate the main file with every drop-in so the
        // effective config is what's checked.
        let mut combined = std::fs::read_to_string("/etc/rsyslog.conf").unwrap_or_default();
        if let Ok(entries) = std::fs::read_dir("/etc/rsyslog.d") {
            let mut confs: Vec<_> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("conf"))
                .collect();
            confs.sort();
            for p in confs {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    combined.push('\n');
                    combined.push_str(&text);
                }
            }
        }
        let rsyslog_conf = if combined.trim().is_empty() {
            None
        } else {
            Some(combined)
        };
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

    #[test]
    fn detects_module_and_action_forwarding_syntax() {
        // omfwd and the action() object form are what modern drop-ins use — checking only for `@`
        // reported these hosts as not forwarding, a false positive on BLWK-LOG-002.
        for cfg in [
            "*.*  action(type=\"omfwd\" target=\"logs.example.com\" port=\"514\" protocol=\"tcp\")\n",
            "module(load=\"omfwd\")\n*.* :omfwd:logs.example.com\n",
        ] {
            let fact = detect_logging_state(true, Some(cfg));
            assert_eq!(
                fact.get("rsyslog_forwards_remote").unwrap(),
                &Value::Bool(true),
                "should detect forwarding in: {cfg}"
            );
        }
    }
}
