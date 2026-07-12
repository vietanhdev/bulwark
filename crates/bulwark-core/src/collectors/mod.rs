mod authorized_keys;
mod banners;
mod clamav;
mod cron;
pub mod file_integrity;
mod file_permissions;
mod grub;
mod logging;
mod login_defs;
mod mac;
mod module_blacklist;
mod network_interfaces;
mod ports;
mod process_accounting;
mod shell_history;
pub(crate) mod sshd;
mod sudoers;
mod sysctl;
mod systemd;

use crate::models::Fact;

/// A collector produces zero or more fact rows describing one slice of host state.
/// List-shaped collectors (ports, cron entries, ...) produce one row per item;
/// rules are evaluated once per row (§5 of the design doc).
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;

    /// Cheap precondition check (e.g. "does /etc/systemd even exist"). A collector that
    /// isn't applicable is skipped and excluded from coverage stats, never reported as a
    /// false "clean" (design doc §8, failure mode row 4).
    fn is_applicable(&self) -> bool {
        true
    }

    /// True for collectors that read root-only paths (e.g. `/etc/sudoers`). The engine
    /// skips these unless running with elevated privilege, and reports the skip explicitly
    /// rather than letting them fail as an opaque I/O error (design doc §4, §8).
    fn requires_privilege(&self) -> bool {
        false
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>>;
}

pub fn all_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(sshd::SshdConfigCollector),
        Box::new(systemd::SystemdUnitsCollector),
        Box::new(ports::ListeningPortsCollector),
        Box::new(cron::CronEntriesCollector),
        Box::new(authorized_keys::AuthorizedKeysCollector),
        Box::new(sysctl::SysctlKernelCollector),
        Box::new(mac::MacStatusCollector),
        Box::new(file_permissions::FilePermissionsCollector),
        Box::new(sudoers::SudoersCollector),
        Box::new(login_defs::LoginDefsCollector),
        Box::new(logging::LoggingCollector),
        Box::new(shell_history::ShellHistoryConfigCollector),
        Box::new(clamav::ClamavStatusCollector),
        Box::new(file_integrity::FileIntegrityCollector),
        Box::new(file_integrity::FileIntegrityPrivilegedCollector),
        Box::new(network_interfaces::NetworkInterfacesCollector),
        Box::new(banners::BannersCollector),
        Box::new(process_accounting::ProcessAccountingCollector),
        Box::new(module_blacklist::ModuleBlacklistCollector),
        Box::new(grub::GrubPasswordCollector),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_collectors_have_unique_non_empty_names() {
        let collectors = all_collectors();
        assert_eq!(collectors.len(), 20);
        let mut names: Vec<&str> = collectors.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            collectors.len(),
            "collector names must be unique — a duplicate silently shadows the earlier one \
             in engine::run_scan's facts_by_collector map"
        );
        assert!(names.iter().all(|n| !n.is_empty()));
    }
}
