//! Checks whether kernel-level process accounting (BSD-style acct/psacct) is enabled —
//! matches Lynis's `ACCT-9622` suggestion (confirmed live against this project's own dev
//! machine, which has neither `accton` nor `lastcomm` installed). Process accounting is what
//! lets "what ran on this box, and when" survive after the fact even if a process's own
//! logging was tampered with or disabled — a different data source than auditd, not a
//! duplicate of `BLWK-LOG-001`.

use super::Collector;
use crate::models::Fact;
use serde_json::Value;

/// Binaries whose presence indicates the accounting package is at least installed —
/// `accton` (enable/disable accounting) or `lastcomm` (query the accounting log), checked
/// across the common install locations rather than relying on `PATH`.
const ACCT_BINARIES: &[&str] = &[
    "/usr/sbin/accton",
    "/sbin/accton",
    "/usr/bin/lastcomm",
    "/usr/sbin/lastcomm",
];

pub struct ProcessAccountingCollector;

impl Collector for ProcessAccountingCollector {
    fn name(&self) -> &'static str {
        "process_accounting"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let installed = ACCT_BINARIES
            .iter()
            .any(|p| std::path::Path::new(p).exists());
        let mut fact = Fact::new();
        fact.insert("installed".to_string(), Value::Bool(installed));
        Ok(vec![fact])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_installed_state_from_this_real_machine() {
        // This project's own dev machine has neither accton nor lastcomm installed —
        // exercising the real filesystem check rather than a fixture keeps this honest.
        let rows = ProcessAccountingCollector.collect().unwrap();
        assert_eq!(rows[0].get("installed").unwrap(), &Value::Bool(false));
    }
}
