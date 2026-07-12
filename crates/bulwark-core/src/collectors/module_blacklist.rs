//! Checks whether a curated set of rarely-needed, historically-exploited kernel modules are
//! blocked from auto-loading — matches Lynis's `NETW-3200` (uncommon network protocols) and
//! `USB-1000` (USB storage) suggestions. These protocol families have a documented history of
//! local-privilege-escalation bugs reachable by an unprivileged user simply opening a socket
//! of that family, which triggers on-demand module autoloading — blacklisting is the standard
//! mitigation when the protocol genuinely isn't needed.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::path::Path;

/// `usb-storage` is watched separately from the network protocols (different threat: physical
/// USB exfiltration/BadUSB, not remote LPE) but checked with the identical mechanism, so one
/// collector covers both rather than two near-identical ones.
const WATCHED_MODULES: &[&str] = &["dccp", "sctp", "rds", "tipc", "usb-storage"];

/// True if any modprobe.d line blocks `module` from loading — either the classic
/// `blacklist <module>` form, or the stronger `install <module> /bin/true` (or `/bin/false`)
/// form, which (unlike a bare blacklist entry) also stops something that explicitly
/// `modprobe`s the module by name rather than relying on autoload.
pub fn is_blacklisted(module: &str, modprobe_d_text: &str) -> bool {
    modprobe_d_text.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        if let Some(rest) = line.strip_prefix("blacklist") {
            return rest.split_whitespace().next() == Some(module);
        }
        if let Some(rest) = line.strip_prefix("install") {
            let mut parts = rest.split_whitespace();
            return parts.next() == Some(module)
                && matches!(parts.next(), Some("/bin/true") | Some("/bin/false"));
        }
        false
    })
}

pub struct ModuleBlacklistCollector;

impl Collector for ModuleBlacklistCollector {
    fn name(&self) -> &'static str {
        "module_blacklist"
    }

    fn is_applicable(&self) -> bool {
        Path::new("/etc/modprobe.d").is_dir()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut combined = String::new();
        if let Ok(entries) = std::fs::read_dir("/etc/modprobe.d") {
            for entry in entries.flatten() {
                if let Ok(text) = std::fs::read_to_string(entry.path()) {
                    combined.push_str(&text);
                    combined.push('\n');
                }
            }
        }

        Ok(WATCHED_MODULES
            .iter()
            .map(|module| {
                let mut fact = Fact::new();
                fact.insert("module".to_string(), Value::String(module.to_string()));
                fact.insert(
                    "blacklisted".to_string(),
                    Value::Bool(is_blacklisted(module, &combined)),
                );
                fact
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_bare_blacklist_entry() {
        let text = "blacklist dccp\n";
        assert!(is_blacklisted("dccp", text));
        assert!(!is_blacklisted("sctp", text));
    }

    #[test]
    fn detects_an_install_bin_true_entry() {
        let text = "install usb-storage /bin/true\n";
        assert!(is_blacklisted("usb-storage", text));
    }

    #[test]
    fn ignores_comments_and_unrelated_lines() {
        let text = "# blacklist dccp\nblacklist unrelated-module\ninstall dccp /sbin/modprobe --ignore-install dccp\n";
        // The commented-out line and the unrelated module don't count; a real `install`
        // passthrough to modprobe (not /bin/true|false) doesn't block loading either.
        assert!(!is_blacklisted("dccp", text));
    }

    #[test]
    fn no_watched_module_is_blacklisted_on_this_real_machine() {
        // Verified directly against this project's own dev machine's real /etc/modprobe.d
        // before writing this collector — none of the five watched modules are blacklisted.
        let rows = ModuleBlacklistCollector.collect().unwrap();
        assert_eq!(rows.len(), 5);
        for row in &rows {
            assert_eq!(row.get("blacklisted").unwrap(), &Value::Bool(false));
        }
    }
}
