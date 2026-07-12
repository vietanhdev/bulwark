//! Skeleton for macOS's persistence analog to `systemd::SystemdUnitsCollector` — a rogue
//! LaunchAgent/LaunchDaemon plist (`~/Library/LaunchAgents`, `/Library/LaunchAgents`,
//! `/Library/LaunchDaemons`) is macOS's version of the same "run this on every login/boot"
//! persistence primitive `BLWK-PERSIST-001/002` watch for on Linux.
//!
//! Deliberately not implemented beyond this skeleton: there is no macOS machine available to
//! build and verify a real plist parser against (see docs/guide/architecture.md's Profiles
//! section) — a stub that silently claimed to work without ever having run for real would be
//! worse than one that's honestly `todo!()`. `supported_os()` gates this out of every scan on
//! every OS but macOS, and `is_applicable()` gates it out unconditionally on top of that as a
//! second, redundant safety net — this collector's `collect()` cannot run on this project's
//! own Linux CI/dev machines by construction, not just by convention.

use super::Collector;
use crate::models::{Fact, OperatingSystem};

const MACOS_ONLY: &[OperatingSystem] = &[OperatingSystem::Macos];

pub struct LaunchdPersistenceCollector;

impl Collector for LaunchdPersistenceCollector {
    fn name(&self) -> &'static str {
        "launchd_persistence"
    }

    fn supported_os(&self) -> &'static [OperatingSystem] {
        MACOS_ONLY
    }

    fn is_applicable(&self) -> bool {
        // Never true today — see module docs. Once a real macOS dev/CI machine is
        // available, this becomes "do the LaunchAgents/LaunchDaemons directories exist,"
        // matching the pattern every other collector in this crate already follows.
        false
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        anyhow::bail!(
            "launchd_persistence is not yet implemented — needs a real macOS machine to build \
             and verify a LaunchAgents/LaunchDaemons plist parser against; unreachable in \
             practice since is_applicable() always returns false"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_applicable_on_this_projects_linux_dev_and_ci_machines() {
        assert!(!LaunchdPersistenceCollector.is_applicable());
    }

    #[test]
    fn only_declares_macos_support() {
        assert_eq!(
            LaunchdPersistenceCollector.supported_os(),
            &[OperatingSystem::Macos]
        );
    }
}
