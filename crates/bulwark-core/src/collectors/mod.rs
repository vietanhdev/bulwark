mod authorized_keys;
pub(crate) mod banners;
mod clamav;
mod credential_stores;
mod cron;
mod dev_tools;
pub mod file_integrity;
mod file_permissions;
mod grub;
mod host_firewall;
mod logging;
mod login_defs;
mod mac;
mod macos_launchd;
mod macos_security;
mod module_blacklist;
mod network_interfaces;
mod ports;
mod process_accounting;
mod python_startup;
mod shell_history;
pub(crate) mod ssh_keys;
mod windows_security;
pub use ssh_keys::{
    protect_unencrypted_keys, BulkProtectionReport, KeyProtectionOutcome, KeyProtectionResult,
};
pub(crate) mod sshd;
mod sudoers;
mod sysctl;
mod systemd;
mod windows_persistence;

use crate::models::{Fact, OperatingSystem};
use std::io::Read;
use std::path::{Path, PathBuf};

const LINUX_ONLY: &[OperatingSystem] = &[OperatingSystem::Linux];
/// For collectors that only read files in the user's home directory (credential stores, SSH keys),
/// which look the same on macOS. Verified against a real Mac before being widened.
pub(crate) const LINUX_AND_MACOS: &[OperatingSystem] =
    &[OperatingSystem::Linux, OperatingSystem::Macos];

/// Upper bound on how much of a file a collector reads into memory. Config and history files are
/// kilobytes in practice; the cap only matters for user-writable inputs (`~/.ssh/authorized_keys`,
/// shell rc files) that a local user could inflate to gigabytes to exhaust memory during a scan
/// that may be running as root. Reading at most this much turns that DoS into a truncated read.
pub(crate) const MAX_COLLECTOR_READ_BYTES: u64 = 4 * 1024 * 1024;

/// Like `std::fs::read_to_string` but reads at most [`MAX_COLLECTOR_READ_BYTES`], so a collector
/// can't be made to allocate unbounded memory by an oversized (possibly attacker-grown) input.
/// Lossy UTF-8 so a stray non-UTF-8 byte truncates a line rather than failing the whole read.
pub(crate) fn read_capped(path: &Path) -> std::io::Result<String> {
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(MAX_COLLECTOR_READ_BYTES).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Home directories of the people a scan is about. Under a privileged scan `$HOME` is root's, so
/// the invoking user's home is added too: `SUDO_USER` for sudo, `PKEXEC_UID` for pkexec (how the
/// GUI elevates). Only directories that exist are returned, deduplicated, in a stable order.
pub(crate) fn user_homes() -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Some(home) = crate::paths::home_var_os().filter(|h| !h.is_empty()) {
        homes.push(PathBuf::from(home));
    }
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    if let Ok(user) = std::env::var("SUDO_USER") {
        homes.extend(passwd_home(&passwd, |name, _| name == user));
    }
    if let Ok(uid) = std::env::var("PKEXEC_UID") {
        homes.extend(passwd_home(&passwd, |_, id| id == uid));
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for h in homes {
        if h.is_dir() && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// The home directory of the first `/etc/passwd` entry matching `pred(name, uid)`.
fn passwd_home(passwd: &str, pred: impl Fn(&str, &str) -> bool) -> Option<PathBuf> {
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.len() >= 6 && pred(f[0], f[2])).then(|| PathBuf::from(f[5]))
    })
}

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
        Box::new(ssh_keys::SshPrivateKeysCollector),
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
        Box::new(macos_security::MacosSecurityCollector),
        Box::new(windows_persistence::WindowsRunKeysCollector),
        Box::new(windows_security::WindowsSecurityCollector),
        Box::new(credential_stores::CredentialStoresCollector),
        Box::new(python_startup::PythonStartupHooksCollector),
        Box::new(python_startup::SupplyChainIocsCollector),
        Box::new(host_firewall::HostFirewallCollector),
        Box::new(dev_tools::DevToolConfigCollector),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_collectors_have_unique_non_empty_names() {
        let collectors = all_collectors();
        assert_eq!(collectors.len(), 30);
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

    #[test]
    fn passwd_home_matches_by_name_or_uid() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000::/home/ana:/bin/zsh\n";
        assert_eq!(
            passwd_home(passwd, |n, _| n == "ana"),
            Some(PathBuf::from("/home/ana"))
        );
        assert_eq!(
            passwd_home(passwd, |_, id| id == "1000"),
            Some(PathBuf::from("/home/ana"))
        );
        assert_eq!(passwd_home(passwd, |_, id| id == "42"), None);
    }
}
