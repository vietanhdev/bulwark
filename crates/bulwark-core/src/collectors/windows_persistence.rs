//! Skeleton for Windows's persistence analog to `systemd::SystemdUnitsCollector` — the
//! registry `Run`/`RunOnce` keys (`HKLM`/`HKCU\...\CurrentVersion\Run`) and Scheduled Tasks
//! are Windows's version of the same "run this on every login/boot" persistence primitive
//! `BLWK-PERSIST-001/002` watch for on Linux.
//!
//! Deliberately not implemented beyond this skeleton: there is no Windows machine available
//! to build and verify a real registry/Task Scheduler reader against (see
//! docs/guide/architecture.md's Profiles section) — a stub that silently claimed to work
//! without ever having run for real would be worse than one that's honestly `todo!()`.
//! `supported_os()` gates this out of every scan on every OS but Windows, and
//! `is_applicable()` gates it out unconditionally on top of that as a second, redundant
//! safety net — this collector's `collect()` cannot run on this project's own Linux CI/dev
//! machines by construction, not just by convention.

use super::Collector;
use crate::models::{Fact, OperatingSystem};

const WINDOWS_ONLY: &[OperatingSystem] = &[OperatingSystem::Windows];

pub struct WindowsRunKeysCollector;

impl Collector for WindowsRunKeysCollector {
    fn name(&self) -> &'static str {
        "windows_run_keys"
    }

    fn supported_os(&self) -> &'static [OperatingSystem] {
        WINDOWS_ONLY
    }

    fn is_applicable(&self) -> bool {
        // Never true today — see module docs. Once a real Windows dev/CI machine is
        // available, this becomes "can the registry actually be queried," matching the
        // pattern every other collector in this crate already follows.
        false
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        anyhow::bail!(
            "windows_run_keys is not yet implemented — needs a real Windows machine to build \
             and verify a registry Run-key/Scheduled Task reader against; unreachable in \
             practice since is_applicable() always returns false"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_applicable_on_this_projects_linux_dev_and_ci_machines() {
        assert!(!WindowsRunKeysCollector.is_applicable());
    }

    #[test]
    fn only_declares_windows_support() {
        assert_eq!(
            WindowsRunKeysCollector.supported_os(),
            &[OperatingSystem::Windows]
        );
    }
}
