use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;
use std::process::Command;

pub struct CronEntriesCollector;

/// Parses one crontab-style file's text into fact rows. `has_user_field` distinguishes
/// `/etc/cron.d/*` syntax (`min hour dom month dow user command`) from a personal
/// `crontab -l` (`min hour dom month dow command`) — the extra column shifts where the
/// command starts.
pub fn parse_cron_text(text: &str, source: &str, has_user_field: bool) -> Vec<Fact> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line
            .splitn(if has_user_field { 7 } else { 6 }, char::is_whitespace)
            .collect();
        let min_fields = if has_user_field { 7 } else { 6 };
        if fields.len() < min_fields {
            continue;
        }
        let schedule = fields[..5].join(" ");
        let command = fields[min_fields - 1].to_string();

        let mut fact = Fact::new();
        fact.insert("source".to_string(), Value::String(source.to_string()));
        fact.insert("schedule".to_string(), Value::String(schedule));
        fact.insert("command".to_string(), Value::String(command));
        rows.push(fact);
    }
    rows
}

impl Collector for CronEntriesCollector {
    fn name(&self) -> &'static str {
        "cron_entries"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = Vec::new();

        // Personal crontab — absence (exit status, "no crontab for user") is normal, not an error.
        if let Ok(output) = Command::new("crontab").arg("-l").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                rows.extend(parse_cron_text(&text, "crontab", false));
            }
        }

        // System-wide drop-ins, world-readable by convention.
        if let Ok(dir) = std::fs::read_dir("/etc/cron.d") {
            for entry in dir.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if name.starts_with('.') || name.eq_ignore_ascii_case("README") {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    rows.extend(parse_cron_text(&text, &format!("/etc/cron.d/{name}"), true));
                }
            }
        }

        Ok(rows)
    }
}

impl CronEntriesCollector {
    #[allow(dead_code)]
    fn cron_d_exists() -> bool {
        Path::new("/etc/cron.d").is_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_personal_crontab() {
        let text = "# comment\n0 6 * * * /home/user/script.sh --flag\n";
        let rows = parse_cron_text(text, "crontab", false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("schedule").unwrap(), "0 6 * * *");
        assert_eq!(
            rows[0].get("command").unwrap(),
            "/home/user/script.sh --flag"
        );
    }

    #[test]
    fn parses_system_cron_d_with_user_field() {
        let text = "0 7 * * * root /usr/local/bin/daily-check.sh\n";
        let rows = parse_cron_text(text, "/etc/cron.d/example", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("command").unwrap(),
            "/usr/local/bin/daily-check.sh"
        );
    }
}
