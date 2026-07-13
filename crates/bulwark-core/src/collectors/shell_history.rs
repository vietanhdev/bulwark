use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

pub struct ShellHistoryConfigCollector;

/// True if a single rc-file line configures the shell to stop recording history. The local signal
/// for MITRE ATT&CK T1070.003 (Clear Command History). The old version matched five exact whole-line
/// strings, which missed essentially every real-world form; this handles the ways people (and
/// attackers) actually write it:
///   * `HISTFILE=/dev/null` or `HISTFILE=` — history is written nowhere.
///   * `HISTSIZE=0` / `HISTFILESIZE=0`, including both on one `export` line.
///   * `unset HISTFILE` (with or without additional vars).
///   * `set +o history` — disables recording outright.
///
/// It tolerates leading indentation, a trailing `# comment`, `export`, quotes, and
/// `;`-separated statements.
fn line_suppresses_history(line: &str) -> bool {
    let line = line.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return false;
    }
    if line.contains("set +o history") {
        return true;
    }
    for stmt in line.split([';', '&']) {
        let stmt = stmt.trim();
        let stmt = stmt.strip_prefix("export ").unwrap_or(stmt).trim();
        if let Some(rest) = stmt.strip_prefix("unset ") {
            if rest.split_whitespace().any(|v| v == "HISTFILE") {
                return true;
            }
            continue;
        }
        for tok in stmt.split_whitespace() {
            if let Some((var, val)) = tok.split_once('=') {
                let val = val.trim_matches(['"', '\'']);
                match var {
                    "HISTFILE" if val.is_empty() || val == "/dev/null" => return true,
                    "HISTSIZE" | "HISTFILESIZE" if val == "0" => return true,
                    _ => {}
                }
            }
        }
    }
    false
}

pub fn detect_history_suppression(rc_text: &str) -> Fact {
    let mut fact = Fact::new();
    let suppressed = rc_text.lines().any(line_suppresses_history);
    fact.insert("history_suppressed".to_string(), Value::Bool(suppressed));
    fact
}

/// The home directories worth inspecting. Under a `sudo`/`pkexec` privileged scan `$HOME` is
/// `/root`, so relying on it alone would check root's rc files and miss the logged-in human's —
/// exactly where a "hide my tracks" line would be. So the invoking user's home (`SUDO_USER`) is
/// included too.
fn user_homes() -> Vec<String> {
    let mut homes = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            homes.push(home);
        }
    }
    if let Ok(user) = std::env::var("SUDO_USER") {
        let home = format!("/home/{user}");
        if !homes.contains(&home) {
            homes.push(home);
        }
    }
    homes
}

impl Collector for ShellHistoryConfigCollector {
    fn name(&self) -> &'static str {
        "shell_history_config"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut combined = String::new();
        // System-wide rc files — read regardless of $HOME, since a suppression planted here hits
        // every user.
        for sys in ["/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"] {
            if let Ok(text) = super::read_capped(Path::new(sys)) {
                combined.push_str(&text);
                combined.push('\n');
            }
        }
        for home in user_homes() {
            for rc in [
                ".bashrc",
                ".zshrc",
                ".zshenv",
                ".profile",
                ".bash_profile",
                ".bash_login",
            ] {
                let path = Path::new(&home).join(rc);
                // Size-capped: user-writable rc files, same memory-exhaustion concern as authorized_keys.
                if let Ok(text) = super::read_capped(&path) {
                    combined.push_str(&text);
                    combined.push('\n');
                }
            }
        }
        Ok(vec![detect_history_suppression(&combined)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_histsize_zero() {
        let fact = detect_history_suppression("export PATH=$PATH:/foo\nexport HISTSIZE=0\n");
        assert_eq!(fact.get("history_suppressed").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn detects_the_real_world_suppression_forms() {
        // Every one of these used to slip past the exact-match check.
        for rc in [
            "  HISTFILE=/dev/null\n",             // indented, /dev/null
            "export HISTSIZE=0 HISTFILESIZE=0\n", // two on one export line
            "set +o history\n",                   // disables recording outright
            "unset HISTFILE HISTSIZE\n",          // unset with extra vars
            "HISTFILE=   # cover my tracks\n",    // empty + inline comment
            "HISTSIZE=0\n",                       // no `export`
        ] {
            assert_eq!(
                detect_history_suppression(rc)
                    .get("history_suppressed")
                    .unwrap(),
                &Value::Bool(true),
                "should flag: {rc:?}"
            );
        }
    }

    #[test]
    fn ordinary_rc_file_is_not_flagged() {
        let fact = detect_history_suppression(
            "alias ll='ls -la'\nexport HISTSIZE=1000\nexport HISTFILE=$HOME/.bash_history\nHISTFILESIZE=2000\n",
        );
        assert_eq!(fact.get("history_suppressed").unwrap(), &Value::Bool(false));
    }
}
