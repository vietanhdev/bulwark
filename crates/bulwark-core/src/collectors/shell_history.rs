use super::Collector;
use crate::models::Fact;
use serde_json::Value;

pub struct ShellHistoryConfigCollector;

/// Detects the common ways a shell is configured to stop recording history — the local
/// signal for MITRE ATT&CK T1070.003 (Clear Command History): `HISTSIZE=0`, `HISTFILE=`
/// (emptied), or `unset HISTFILE` in an rc file.
pub fn detect_history_suppression(rc_text: &str) -> Fact {
    let mut fact = Fact::new();
    let suppressed = rc_text.lines().map(str::trim).any(|l| {
        l == "HISTSIZE=0"
            || l == "export HISTSIZE=0"
            || l == "HISTFILE="
            || l == "export HISTFILE="
            || l == "unset HISTFILE"
    });
    fact.insert("history_suppressed".to_string(), Value::Bool(suppressed));
    fact
}

impl Collector for ShellHistoryConfigCollector {
    fn name(&self) -> &'static str {
        "shell_history_config"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let home = std::env::var("HOME").unwrap_or_default();
        let mut combined = String::new();
        for rc in [".bashrc", ".zshrc", ".profile"] {
            let path = std::path::Path::new(&home).join(rc);
            // Size-capped: user-writable rc files, same memory-exhaustion concern as authorized_keys.
            if let Ok(text) = super::read_capped(&path) {
                combined.push_str(&text);
                combined.push('\n');
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
    fn ordinary_rc_file_is_not_flagged() {
        let fact = detect_history_suppression("alias ll='ls -la'\nexport HISTSIZE=1000\n");
        assert_eq!(fact.get("history_suppressed").unwrap(), &Value::Bool(false));
    }
}
