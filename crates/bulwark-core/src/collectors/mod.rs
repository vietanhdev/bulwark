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
mod macos_launchd;
mod module_blacklist;
mod network_interfaces;
mod ports;
mod process_accounting;
mod shell_history;
pub(crate) mod sshd;
mod sudoers;
mod sysctl;
mod systemd;
mod windows_persistence;

use crate::models::{Fact, OperatingSystem};

const LINUX_ONLY: &[OperatingSystem] = &[OperatingSystem::Linux];

/// A collector produces zero or more fact rows describing one slice of host state.
/// List-shaped collectors (ports, cron entries, ...) produce one row per item;
/// rules are evaluated once per row (§5 of the architecture doc).
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;

    /// Which OS(es) this collector can produce real facts on. The engine skips a collector
    /// entirely — never calling `is_applicable()` or `collect()` — when the host OS isn't in
    /// this list, so a macOS/Windows collector can never touch a Linux-specific path (or
    /// vice versa) by construction, not just by convention. Defaults to Linux-only since
    /// every collector before this field existed was implicitly Linux-only anyway.
    fn supported_os(&self) -> &'static [OperatingSystem] {
        LINUX_ONLY
    }

    /// Cheap precondition check (e.g. "does /etc/systemd even exist"). A collector that
    /// isn't applicable is skipped and excluded from coverage stats, never reported as a
    /// false "clean" (architecture doc §8, failure mode row 4).
    fn is_applicable(&self) -> bool {
        true
    }

    /// True for collectors that read root-only paths (e.g. `/etc/sudoers`). The engine
    /// skips these unless running with elevated privilege, and reports the skip explicitly
    /// rather than letting them fail as an opaque I/O error (architecture doc §4, §8).
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
        Box::new(macos_launchd::LaunchdPersistenceCollector),
        Box::new(windows_persistence::WindowsRunKeysCollector),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_collectors_have_unique_non_empty_names() {
        let collectors = all_collectors();
        assert_eq!(collectors.len(), 22);
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
