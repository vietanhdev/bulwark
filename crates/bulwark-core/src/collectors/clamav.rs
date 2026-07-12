use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::time::SystemTime;

pub struct ClamavStatusCollector;

/// Rootkit/malware detection in Bulwark is deliberately *not* a reimplemented signature
/// engine (design doc §2 non-goals: "shells out to the system's own ClamAV installation
/// ... rather than reimplementing it"). This collector reports whether ClamAV is even
/// installed and how stale its signature database is — the two things that make a
/// present-but-useless install indistinguishable from a real one to a casual glance.
pub fn describe_db_freshness(
    installed: bool,
    db_mtime: Option<SystemTime>,
    now: SystemTime,
) -> Fact {
    let mut fact = Fact::new();
    fact.insert("installed".to_string(), Value::Bool(installed));
    let age_days = db_mtime
        .and_then(|t| now.duration_since(t).ok())
        .map(|d| (d.as_secs() / 86400) as i64);
    match age_days {
        Some(days) => {
            fact.insert("db_age_days".to_string(), Value::from(days));
        }
        None => {
            // No mtime (DB missing entirely, or installed but never updated) is left out
            // of the fact rather than defaulted to 0 or a huge number — a rule reading
            // db_age_days then reports MissingField rather than a misleading value.
        }
    }
    fact
}

impl Collector for ClamavStatusCollector {
    fn name(&self) -> &'static str {
        "clamav_status"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let installed = std::process::Command::new("clamscan")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let db_mtime = ["/var/lib/clamav/daily.cvd", "/var/lib/clamav/daily.cld"]
            .iter()
            .find_map(|p| std::fs::metadata(p).ok().and_then(|m| m.modified().ok()));

        Ok(vec![describe_db_freshness(
            installed,
            db_mtime,
            SystemTime::now(),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn not_installed_has_no_age_field() {
        let fact = describe_db_freshness(false, None, SystemTime::now());
        assert_eq!(fact.get("installed").unwrap(), &Value::Bool(false));
        assert!(!fact.contains_key("db_age_days"));
    }

    #[test]
    fn computes_age_in_days() {
        let now = SystemTime::now();
        let ten_days_ago = now - Duration::from_secs(10 * 86400);
        let fact = describe_db_freshness(true, Some(ten_days_ago), now);
        assert_eq!(fact.get("db_age_days").unwrap(), &Value::from(10));
    }
}
